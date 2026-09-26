import express, { request } from 'express';
import { NextFunction, Request, Response } from 'express';
import endpoints from '../data/endpoints.json'
import {
    CdrConfig, cdrHeaderValidator,
    cdrEndpointValidator,
    cdrScopeValidator,
    cdrResourceValidator,
    EndpointConfig,
    buildErrorMessage,
    DsbStandardError,
    getLinksPaginated,
    getMetaPaginated,
    paginateData,
    IUserService
} from "@cds-au/holder-sdk"

import bodyParser from 'body-parser';
import * as dotenv from 'dotenv';
import cors from 'cors';
import path from 'path';
import { readFileSync } from 'fs';
import * as https from 'https'
import * as http from 'http'
import { DsbCdrUser } from './models/user';
import { cdrAuthorization } from './modules/auth';
import {
    EnergyAccountV2, EnergyBalanceListResponse,
    EnergyBalanceResponse, EnergyBillingListResponseV2, EnergyBillingTransactionV2, EnergyConcession,
    EnergyConcessionsResponse, EnergyDerDetailResponse, EnergyDerListResponse, EnergyDerRecord,
    EnergyInvoiceListResponse, EnergyPaymentSchedule, EnergyPaymentScheduleResponse, EnergyPlan,
    EnergyPlanListResponse, EnergyServicePoint, EnergyServicePointDetail,
    EnergyServicePointDetailResponse, EnergyServicePointListResponse, EnergyUsageListResponse,
    EnergyUsageRead, EnergyInvoice,
    EnergyAccountDetailResponseV3,
    EnergyPlanDetailV3,
    EnergyPlanResponseV3,
    ResponseErrorListV2
} from 'consumer-data-standards/energy';
import { IDatabase } from './services/database.interface';
import { SingleData } from './services/single-data.service';
import { BankingAccountDetailV3, ResponseBankingAccountByIdV3, ResponseBankingAccountListV2, ResponseBankingAccountsBalanceById, ResponseBankingAccountsBalanceList, ResponseBankingDirectDebitAuthorisationList, ResponseBankingPayeeByIdV2, ResponseBankingPayeeListV2, ResponseBankingProductByIdV4, ResponseBankingProductListV2, ResponseBankingScheduledPaymentsListV2, ResponseBankingTransactionById, ResponseBankingTransactionList } from 'consumer-data-standards/banking';
import { StandAloneAuthService } from './modules/standalone-auth-service';
import { IAuthService } from './modules/auth-service.interface';
// import { AuthService } from './modules/auth-service';
import moment from 'moment';
import { PanvaAuthService } from './modules/panva-auth-service';
import session from 'express-session';
import { AcccAuthService } from './modules/accc-auth-service';

dotenv.config();

const exp = express;
const app = express();
let port = `${process.env.APP_LISTENTING_PORT}`;
const authServerType = `${process.env.AUTH_SERVER_TYPE}`;
const useSSL: boolean = `${process.env.USE_SSL}`.toUpperCase() == 'TRUE';

let basePath = '/cds-au/v1';


// This implementation uses a MongoDB. To use some other persistent storage
// you need to implement the IDatabase interface
const connString = `mongodb://${process.env.MONGO_HOSTNAME}:${process.env.MONGO_PORT}`
const corsAllowedOrigin = process.env.CORS_ALLOWED_ORIGINS?.split(",")

console.log(`Connection string is ${connString}`);

var dbService: IDatabase;
var authService: IAuthService;
dbService = new SingleData(connString, process.env.MONGO_DB as string);

// The default token is used when this is run in STANDALONE_MODE, ie no authentication validation is performed
const defaultToken = process.env.DEFAULT_TOKEN;

// the auth server type will determine which implementation of IAuthService will be used.
if (authServerType.toUpperCase() == "STANDALONE") {
    console.log(`Running server without authorisation. The assumed user is ${process.env.LOGIN_ID}`);
     authService = new StandAloneAuthService(dbService, defaultToken);
}
else if (authServerType.toUpperCase() == "ACCC") {
    console.log(`Running server with ACCC IdP authorisation. Required to go through authorisation process`)
    authService = new AcccAuthService(dbService, process.env.CLIENT_ID as string, process.env.CLIENT_SECRET as string);
}
else if (authServerType.toUpperCase() == "PANVA") {
    console.log(`Running server with Panva IdP authorisation. Required to go through authorisation process`)
    authService = new PanvaAuthService(dbService, process.env.CLIENT_ID as string, process.env.CLIENT_SECRET as string);
}
else {
    console.log(`No authorisation mechanism specified. Will not use authorisation`);
    authService = new StandAloneAuthService(dbService, defaultToken);
}



// Add a list of allowed origins.
// If you have more origins you would like to add, you can add them to the array below.
const corsOptions: cors.CorsOptions = {
    origin: corsAllowedOrigin
};
app.use(cors(corsOptions));
app.use(session({
       secret: 'your-secret-key', // Replace with a strong secret key
       resave: false,
       saveUninitialized: true,
       cookie: { secure: false } // Set to true in production with HTTPS
   }));

const router = exp.Router();

const sampleEndpoints = [...endpoints] as EndpointConfig[];

const certFile = path.join(__dirname, '/security', process.env.CERT_FILE as string)
const keyFile = path.join(__dirname, '/security', process.env.CERT_KEY_FILE as string)
const signingPublicKeyFile = path.join(__dirname, '/security/public.json')
const rCert = readFileSync(certFile, 'utf8');
const rKey = readFileSync(keyFile, 'utf8');
const publicKey = readFileSync(signingPublicKeyFile, 'utf8');

const endpointValidatorOptions: CdrConfig = {
    endpoints: sampleEndpoints
}

const headerValidatorOptions: CdrConfig = {
    endpoints: sampleEndpoints
}

// The user service which provides the callback function for the 
// cdrResourceValidator middleware function to accounts associated with user
var userService: IUserService = {
    getUser: function (req: Request): DsbCdrUser | undefined {
        return req.session?.cdrUser;
    }
};

const excludedPaths: string[] = ["/health", "/login-data", "/login-data/all", "/login-data/energy", "/login-data/banking", "/jwks"]

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.use(unless(cdrAuthorization(authService, endpointValidatorOptions), excludedPaths));
app.use(unless(cdrEndpointValidator(endpointValidatorOptions), excludedPaths));
app.use(unless(cdrHeaderValidator(headerValidatorOptions), excludedPaths));
app.use(unless(cdrScopeValidator(userService), excludedPaths));
app.use(unless(cdrResourceValidator(userService), excludedPaths));


app.use('/', router);


async function initaliseApp() {
    try {
        const options = {
            key: rKey,
            cert: rCert
        }
        console.log(`Connecting to database : ${connString}`);
        await dbService.connectDatabase();
        authService.initAuthService();
        console.log(`Connected.`);
        let portSSL = `${process.env.APP_LISTENTING_PORT_SSL}`;
        https.createServer(options, app)
            .listen(portSSL, () => {
                console.log(`Server started (SSL). Listening on port ${portSSL}`);
            })
        let port = `${process.env.APP_LISTENTING_PORT}`;
        http.createServer(app)
        .listen(port, () => {
            console.log(`Server started. Listening on port ${port}`);
        })  
        
    } catch (e: any) {
        console.log(`FATAL: could not start server${e?.message}`);
    }
}

// this endpoint requires authentication
app.get(`/health`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        res.send(`Service is running....`);
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get the jwks signing key. This is called by the auth server
app.get(`/jwks`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        res.contentType('application/json')
        //const jwkFile = path.join(__dirname, '/security/public.json')
        const jwk = JSON.parse(readFileSync(signingPublicKeyFile, 'utf8'));
        console.log(jwk);
        res.send(jwk);
    } catch(err: any) {
        console.log(`Could not get Jwk: ${err?.message}`)
    }
    
});


// function used to determine if the middleware is to be bypassed for the given 'paths'
function unless(middleware: any, paths: string[]) {
    return function (req: Request, res: Response, next: NextFunction) {
        // Checks whether an element is even
        let pathCheck = false
        for (let i=0; i < paths?.length; i++){
            if (paths[i].toUpperCase() == req.path.toUpperCase())
            {
                pathCheck = true;
                break;
            }
            
        }
        pathCheck ? next() : middleware(req, res, next);
    };
};

// anything /energy/accounts/<something-else> needs  to be routed like this 
router.get(`${basePath}/energy/accounts/:accountId`, async (req, res) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        if ((await isEnergyAccountForUser(req, req.params.accountId)) == false) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_ENERGY_ACCOUNT, `Invalid Energy Account: ${req.params?.accountId}`)
            res.status(404).json(errorList);
            return;
        }
        var excludes = ["invoices", "billing", "balances"];
        if (excludes.indexOf(req.params?.accountId) == -1) {
            let data: any | undefined = await dbService.getEnergyAccountDetails(authService?.getUser(req)?.customerId as string, req.params?.accountId)
            if (data == null) {
                let errorList = buildErrorMessage(DsbStandardError.UNAVAILABLE_BANK_ACCOUNT, `Unavailable Energy Account: ${req.params?.accountId}`)
                res.status(404).json(errorList);
                return;
            } else {
                let resp: EnergyAccountDetailResponseV3 = {
                    data: data,
                    links: {
                        self: req.protocol + '://' + req.get('host') + req.originalUrl
                    },
                    meta: {}
                }
                res.send(resp);
                return;
            }
        }
        if (req.params?.accountId == "invoices") {
            let allowedParams: string[] = [
                "oldest-date", "newest-date", "page", "page-size"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result: EnergyInvoice[] = await dbService.getBulkInvoicesForUser(authService?.getUser(req)?.customerId as string, req?.query)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {
                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: EnergyInvoiceListResponse = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            invoices: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }

        if (req.params?.accountId == "billing") {
            let allowedParams: string[] = [
                "oldest-time", "newest-time", "page", "page-size"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result = await dbService.getBulkBilllingForUser(authService?.getUser(req)?.customerId as string, req.query)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {

                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: EnergyBillingListResponseV2 = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            transactions: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }

        if (req.params?.accountId == "balances") {
            let result: any[] = await dbService.getBulkBalancesForUser(authService?.getUser(req)?.customerId as string)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {

                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: EnergyBalanceListResponse = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            balances: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
})

// anything /energy/electricity/servicepoints/<something-else> needs  to be routed like this 
router.get(`${basePath}/energy/electricity/servicepoints/:servicePointId`, async (req, res) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        var excludes = ["usage", "der"];
        if (excludes.indexOf(req.params?.servicePointId) == -1) {
            let allowedParams: string[] = [
                "page", "page-size"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result: EnergyServicePointDetail = await dbService.getServicePointDetails(authService?.getUser(req)?.customerId as string, req.params?.servicePointId)
            if (result == null) {
                let errorList = buildErrorMessage(DsbStandardError.INVALID_SERVICE_POINT, `Invalid Service Point: ${req.params?.servicePointId}`)
                res.status(404).json(errorList);
                return;
            } else {
                let resp: EnergyServicePointDetailResponse = {
                    data: result,
                    links: {
                        self: req.protocol + '://' + req.get('host') + req.originalUrl
                    }
                }
                res.send(resp);
                return;
            }
        }
        if (req.params?.servicePointId == "usage") {
            console.log(`Received request on ${port} for ${req.url}`);
            let allowedParams: string[] = [
                "oldest-date", "newest-date", "interval-reads", "page", "page-size"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result: EnergyUsageRead[] = await dbService.getBulkUsageForUser(authService?.getUser(req)?.customerId as string, req?.query)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {

                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: EnergyUsageListResponse = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            reads: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }
        if (req.params?.servicePointId == "der") {
            console.log(`Received request on ${port} for ${req.url}`);
            let allowedParams: string[] = [
                "page", "page-size"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result: EnergyDerRecord[] = await dbService.getBulkDerForUser(authService?.getUser(req)?.customerId as string)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {

                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: EnergyDerListResponse = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            derRecords: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
})

// this endpoint requires authentication
app.get(`${basePath}/energy/accounts`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size", "open-status"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyAccountV2[] = await dbService.getEnergyAccounts(authService?.getUser(req)?.customerId as string, authService?.getUser(req)?.accountsEnergy as string[], req.query);
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                // TODO there is a bug in the schema definitions. Once that is resolved revert to the use of type , eg EnergyListResponseV2
                let listResponse: any = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        accounts: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// tget list of service points, returns EnergyServicePointListResponse
app.get(`${basePath}/energy/electricity/servicepoints`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyServicePoint[] = await dbService.getServicePoints(authService?.getUser(req)?.customerId as string);
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyServicePointListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        servicePoints: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

app.get(`${basePath}/common/customer/detail`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let result = await dbService.getCustomerDetails(authService?.getUser(req)?.customerId as string);
        if (result == null || result?.data == null) {
            res.sendStatus(404);
        } else {
            result.links.self = req.protocol + '://' + req.get('host') + req.originalUrl;
            res.send(result);
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

app.get(`${basePath}/common/customer`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let result = await dbService.getCustomerDetails(authService?.getUser(req)?.customerId as string);
        if (result == null || result?.data == null) {
            res.sendStatus(404);
        } else {
            result.links.self = req.protocol + '://' + req.get('host') + req.originalUrl;
            res.send(result);
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

app.get(`${basePath}/energy/plans/:planId`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let data: EnergyPlanDetailV3 | null = await dbService.getEnergyPlanDetails(req.params.planId)
        if (data == null) {
            let errorList = buildErrorMessage(DsbStandardError.RESOURCE_NOT_FOUND, `Resource Not Found: ${req.params?.planId}`)
            res.status(404).json(errorList);
            return;
        } else {
            let result: EnergyPlanResponseV3 = {
                data: data,
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                }
            }
            res.send(result);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

// this endpoint does NOT require authentication
app.get(`${basePath}/energy/plans/`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "effective", "fuelType", "updated-since", "type", "brand", "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyPlan[] = await dbService.getEnergyAllPlans(req.query);
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyPlanListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        plans: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get usage fort a service point, returns EnergyUsageListResponse
app.get(`${basePath}/energy/electricity/servicepoints/:servicePointId/usage`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "oldest-date", "newest-date", "interval-reads", "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyUsageRead[] = await dbService.getUsageForServicePoint(authService?.getUser(req)?.customerId as string, req.params.servicePointId, req?.query)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_SERVICE_POINT, `Invalid Service Point: ${req.params.servicePointId}`)
            res.status(404).json(errorList);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyUsageListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        reads: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get der for a service point, returns EnergyDerDetailResponse
app.get(`${basePath}/energy/electricity/servicepoints/:servicePointId/der`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        // find service point in user object, if it is not a service point associated with
        if ((await isServicePointsForUser(req, req.params.servicePointId)) == false) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_SERVICE_POINT, `Invalid Service Point: ${req.params.servicePointId}`)
            res.status(404).json(errorList);
            return;
        }
        let data: EnergyDerRecord | undefined = await dbService.getDerForServicePoint(req.session.cdrUser?.customerId as string, req.params.servicePointId);
        if (data == null) {
            let errorList = buildErrorMessage(DsbStandardError.UNAVAILABLE_SERVICE_POINT, `Unavailable Service Point: ${req.params.servicePointId}`)
            res.status(404).json(errorList);
            return;
        } else {
            let ret: EnergyDerDetailResponse = {
                data: data,
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                },
                meta: {}
            }
            res.send(ret);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.status(500);
        return;
    }
});

// get der for a list service point, returns EnergyDerListResponse
app.post(`${basePath}/energy/electricity/servicepoints/der`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyDerRecord[] = await dbService.getDerForMultipleServicePoints(authService?.getUser(req)?.customerId as string, req.body?.data?.servicePointIds);
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyDerListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        derRecords: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

// get invoices for account, returns EnergyInvoiceListResponse
app.get(`${basePath}/energy/accounts/:accountId/invoices`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "oldest-date", "newest-date", "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyInvoice[] = await dbService.getInvoicesForAccount(authService?.getUser(req)?.customerId as string, req.params.accountId, req.query)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_ENERGY_ACCOUNT, `Invalid Energy Account: ${req.params?.accountId}`);
            res.status(404).json(errorList);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyInvoiceListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        invoices: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get invoices for account, returns EnergyInvoiceListResponse
app.post(`${basePath}/energy/accounts/invoices`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received POST request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "oldest-date", "newest-date", "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyInvoice[] = await dbService.getInvoicesForMultipleAccounts(authService?.getUser(req)?.customerId as string, req.body?.data?.accountIds, req.query)
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyInvoiceListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        invoices: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});


// get invoices for account, returns EnergyInvoiceListResponse
app.post(`${basePath}/energy/accounts/balances`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received POST request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: any[] = await dbService.getBalancesForMultipleAccount(authService?.getUser(req)?.customerId as string, req.body?.data?.accountIds)
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyBalanceListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        balances: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get invoices for account, returns EnergyInvoiceListResponse
app.post(`${basePath}/energy/electricity/servicepoints/usage`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "oldest-date", "newest-date", "interval-reads", "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyUsageRead[] = await dbService.getUsageForMultipleServicePoints(authService?.getUser(req)?.customerId as string, req.body?.data?.servicePointIds, req.query)
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyUsageListResponse = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        reads: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get concessions for account, returns EnergyConcessionsResponse
app.get(`${basePath}/energy/accounts/:accountId/concessions`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let result: EnergyConcession[] | undefined = await dbService.getConcessionsForAccount(authService?.getUser(req)?.customerId as string, req.params?.accountId)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_ENERGY_ACCOUNT, `Invalid Energy Account: ${req.params.accountId}`)
            res.status(404).json(errorList);
            return;
        } else {
            let ret: EnergyConcessionsResponse = {
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                },
                meta: {},
                data: {
                    concessions: result
                }
            }
            res.send(ret);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get balance for account, returns EnergyBalanceResponse
app.get(`${basePath}/energy/accounts/:accountId/balance`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let st = `Received request on ${port} for ${req.url}`;
        let result = await dbService.getBalanceForAccount(authService?.getUser(req)?.customerId as string, req.params?.accountId)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_ENERGY_ACCOUNT, `Invalid Energy Account: ${req.params.accountId}`)
            res.status(404).json(errorList);
            return;
        } else {
            let ret: EnergyBalanceResponse = {
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                },
                meta: {},
                data: {
                    balance: result
                }
            }
            res.send(ret);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get payment schedule for account, returns EnergyPaymentScheduleResponse
app.get(`${basePath}/energy/accounts/:accountId/payment-schedule`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let result: EnergyPaymentSchedule[] = await dbService.getPaymentSchedulesForAccount(authService?.getUser(req)?.customerId as string, req.params?.accountId)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_ENERGY_ACCOUNT, `Invalid Energy Account: ${req.params.accountId}`)
            res.status(404).json(errorList);
            return;
        } else {
            let ret: EnergyPaymentScheduleResponse = {
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                },
                meta: {},
                data: {
                    paymentSchedules: result
                }
            }
            res.send(ret);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get payment schedule for account, returns EnergyPaymentScheduleResponse
app.get(`${basePath}/energy/accounts/:accountId/billing`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size","newest-time","oldest-time"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyBillingTransactionV2[] = await dbService.getBillingForAccount(authService?.getUser(req)?.customerId as string, req.params?.accountId, req?.query)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_ENERGY_ACCOUNT, `Invalid Energy Account: ${req.params.accountId}`)
            res.status(404).json(errorList);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyBillingListResponseV2 = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        transactions: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// get billing for a number of accounts
app.post(`${basePath}/energy/accounts/billing`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "oldest-time", "newest-time", "page", "page-size"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result: EnergyBillingTransactionV2[] = await dbService.getBillingForMultipleAccounts(authService?.getUser(req)?.customerId as string, req.body?.data?.accountIds, req.query)
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {

            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: EnergyBillingListResponseV2 = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        transactions: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

/******************* BANKING DATA  *********************************/

// anything /energy/accounts/<something-else> needs  to be routed like this 
router.get(`${basePath}/banking/accounts/:accountId`, async (req, res) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        if ((await isBankAccountForUser(req, req.params.accountId)) == false) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_BANK_ACCOUNT, `Invalid Bank Account: ${req.params.accountId}`)
            res.status(404).json(errorList);
            return;
        }
        var excludes = ["direct-debits", "balances"];
        if (excludes.indexOf(req.params?.accountId) == -1) {
            let data: BankingAccountDetailV3 | undefined = await dbService.getAccountDetail(authService?.getUser(req)?.customerId as string, req.params.accountId)
            if (data == null) {
                let errorList = buildErrorMessage(DsbStandardError.UNAVAILABLE_BANK_ACCOUNT, `Unavailable Bank Account: ${req.params.accountId}`);
                res.status(404).json(errorList);
                return;
            } else {
                let result: ResponseBankingAccountByIdV3 = {
                    data: data,
                    links: {
                        self: req.protocol + '://' + req.get('host') + req.originalUrl
                    }
                }
                res.send(result);
                return;
            }
        }
        if (req.params?.accountId == "balances") {
            let allowedParams: string[] = [
                "page", "page-size", "product-category", "product-category", "open-status", "is-owned"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result = await dbService.getBulkBalances(authService?.getUser(req)?.customerId as string, req.query)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {
                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: ResponseBankingAccountsBalanceList = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            balances: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }
        if (req.params?.accountId == "direct-debits") {
            let allowedParams: string[] = [
                "page", "page-size", "product-category", "product-category", "open-status", "is-owned"
            ]
            let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
            if (errorList != undefined) {
                res.status(400).json(errorList);
                return;
            }
            let result = await dbService.getBulkDirectDebits(authService?.getUser(req)?.customerId as string, req.query)
            if (result == null) {
                res.sendStatus(404);
                return;
            } else {
                let paginatedData = paginateData(result, req.query);
                // check if this is an error object
                if (paginatedData?.errors != null) {
                    res.statusCode = 422;
                    // In this case paginatedData is actually an error object
                    res.send(paginatedData);
                    return;
                }
                else {
                    let listResponse: ResponseBankingDirectDebitAuthorisationList = {
                        links: getLinksPaginated(req, result.length),
                        meta: getMetaPaginated(result.length, req.query),
                        data: {
                            directDebitAuthorisations: paginatedData
                        }
                    }
                    res.send(listResponse);
                    return;
                }
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
})

// this endpoint does NOT require authentication
app.get(`${basePath}/banking/products/`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        let allowedParams: string[] = [
            "page", "page-size", "product-category", "effective", "updated-since", "brand"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let q = req.query as object;
        let result = await dbService.getAllBankingProducts(q);
        if (result == null) {
            res.sendStatus(404);
            return;
        }
        else {
            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: ResponseBankingProductListV2 = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        products: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/products/:productId`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let data = await dbService.getBankingProductDetails(req.params.productId)
        if (data == null) {
            let errorList = buildErrorMessage(DsbStandardError.RESOURCE_NOT_FOUND, `Resource Not Found: ${req.params.productId}`);
            res.status(404).json(errorList);
            return;
        } else {
            let result: ResponseBankingProductByIdV4 = {
                data: data,
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                }
            }
            res.send(result);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/accounts/`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size", "product-category", "product-category", "open-status", "is-owned"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result = await dbService.getAccounts(authService?.getUser(req)?.customerId as string, authService?.getUser(req)?.accountsBanking as string[], req.query)

        let paginatedData = paginateData(result, req.query);
        // check if this is an error object
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingAccountListV2 = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    accounts: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});


app.get(`${basePath}/banking/accounts/:accountId/balance`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let data = await dbService.getAccountBalance(authService?.getUser(req)?.customerId as string, req.params.accountId)
        if (data == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_BANK_ACCOUNT, `Invalid Bank Account: ${req?.params?.accountId}`);
            res.status(404).json(errorList);
            return;
        } else {
            let result: ResponseBankingAccountsBalanceById = {
                data: data,
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                }
            }
            res.send(result);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});


app.post(`${basePath}/banking/accounts/balances`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getBalancesForSpecificAccounts(authService?.getUser(req)?.customerId as string, req.body?.data?.accountIds, req.query)
        if (result == null) {
            res.sendStatus(404);
            return;
        } else {
            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: ResponseBankingAccountsBalanceList = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        balances: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/accounts/:accountId/transactions`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let allowedParams: string[] = [
            "page", "page-size", "oldest-time", "newest-time", "min-amount", "max-amount"
        ]
        let errorList: ResponseErrorListV2 | undefined = validateQueryParameters(req.query, allowedParams);
        if (errorList != undefined) {
            res.status(400).json(errorList);
            return;
        }
        let result = await dbService.getTransationsForAccount(authService?.getUser(req)?.customerId as string, req.params.accountId, req.query)
        if (result == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_BANK_ACCOUNT, `Invalid Bank Account: ${req.params?.accountId}`)
            res.status(404).json(errorList);
            return;
        } else {
            let paginatedData = paginateData(result, req.query);
            // check if this is an error object
            if (paginatedData?.errors != null) {
                res.statusCode = 422;
                // In this case paginatedData is actually an error object
                res.send(paginatedData);
                return;
            }
            else {
                let listResponse: ResponseBankingTransactionList = {
                    links: getLinksPaginated(req, result.length),
                    meta: getMetaPaginated(result.length, req.query),
                    data: {
                        transactions: paginatedData
                    }
                }
                res.send(listResponse);
                return;
            }
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/accounts/:accountId/transactions/:transactionId`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let data = await dbService.getTransactionDetail(authService?.getUser(req)?.customerId as string, req.params.accountId, req.params.transactionId)
        if (data == null) {
            let errorList = buildErrorMessage(DsbStandardError.INVALID_BANK_ACCOUNT, `Invalid Bank Account: ${req?.params?.accountId}`);
            res.status(404).json(errorList);
            return;
        } else {
            // TODO the ResponseBankingTransactionById does not reference BankingTransactionDetail
            // Once this has been fixed in the typedefs the 
            let result: any = {
                data: data,
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                }
            }
            res.send(result);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/payees/`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getPayees(authService?.getUser(req)?.customerId as string, req.query)
        let paginatedData = paginateData(result, req.query);
        // check if this is an error object
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingPayeeListV2 = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    payees: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/payees/:payeeId`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let data = await dbService.getPayeeDetail(authService?.getUser(req)?.customerId as string, req.params.payeeId)
        if (data == null) {
            let errorList = buildErrorMessage(DsbStandardError.RESOURCE_NOT_FOUND, `Resource Not Found: ${req?.params?.payeeId}`);
            res.status(404).json(errorList);
            return;
        } else {
            let result: ResponseBankingPayeeByIdV2 = {
                data: data,
                links: {
                    self: req.protocol + '://' + req.get('host') + req.originalUrl
                }
            }
            res.send(result);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/payments/scheduled`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getBulkScheduledPayments(authService?.getUser(req)?.customerId as string, req.query)
        // check if this is an error object
        let paginatedData = paginateData(result, req.query);
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingScheduledPaymentsListV2 = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    scheduledPayments: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.post(`${basePath}/banking/payments/scheduled`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getScheduledPaymentsForAccountList(authService?.getUser(req)?.customerId as string, req.body?.data?.accountIds, req.query)
        // check if this is an error object
        let paginatedData = paginateData(result, req.query);
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingScheduledPaymentsListV2 = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    scheduledPayments: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/accounts/:accountId/payments/scheduled`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getScheduledPaymentsForAccount(authService?.getUser(req)?.customerId as string, req.params.accountId, req.query)
        // check if this is an error object
        let paginatedData = paginateData(result, req.query);
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingScheduledPaymentsListV2 = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    scheduledPayments: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.get(`${basePath}/banking/accounts/:accountId/direct-debits`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getDirectDebitsForAccount(authService?.getUser(req)?.customerId as string, req.params.accountId, req.query)
        // check if this is an error object
        let paginatedData = paginateData(result, req.query);
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingDirectDebitAuthorisationList = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    directDebitAuthorisations: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

app.post(`${basePath}/banking/accounts/direct-debits`, async (req: Request, res: Response, next: NextFunction) => {
    console.log(`Received request on ${port} for ${req.url}`);
    try {
        console.log(`Received request on ${port} for ${req.url}`);

        let result = await dbService.getDirectDebitsForAccountList(authService?.getUser(req)?.customerId as string, req.body?.data?.accountIds, req.query)
        // check if this is an error object
        let paginatedData = paginateData(result, req.query);
        if (paginatedData?.errors != null) {
            res.statusCode = 422;
            // In this case paginatedData is actually an error object
            res.send(paginatedData);
            return;
        }
        else {
            let listResponse: ResponseBankingDirectDebitAuthorisationList = {
                links: getLinksPaginated(req, result.length),
                meta: getMetaPaginated(result.length, req.query),
                data: {
                    directDebitAuthorisations: paginatedData
                }
            }
            res.send(listResponse);
            return;
        }
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }

});

// Get the information required by the Auth server to displaythe login screen
app.get(`/login-data/:sector`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let qry: any = req.query
        let customers = await dbService.getLoginInformation(req.params?.sector, qry["loginId"])
        if (customers == null) {
            console.log(`Error: customer not found ${req.params?.loginId}`);
            res.status(404).json('Not Found');
            return;
        }
        let result = { Customers: customers };
        res.send(result);
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// Get the information required by the Auth server to displaythe login screen
app.get(`/login-data`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        let qry: any = req.query
        let customers = await dbService.getLoginInformation('ALL', qry["loginId"])
        if (customers == null) {
            console.log(`Error: customer not found ${req.params?.loginId}`);
            res.status(404).json('Not Found');
            return;
        }
        let result = { Customers: customers };
        res.send(result);
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});

// this endpoint requires authentication
app.get(`/health`, async (req: Request, res: Response, next: NextFunction) => {
    try {
        console.log(`Received request on ${port} for ${req.url}`);
        res.send(`Service is running....`);
    } catch (e) {
        console.log('Error:', e);
        res.sendStatus(500);
    }
});


async function isServicePointsForUser(req: Request, servicePointId: string): Promise<boolean> {
    let retVal: boolean = false;
    if (authService != null) {
        let idx = (await userService.getUser(req))?.energyServicePoints?.findIndex((x: string) => servicePointId);
        retVal = (idx != null) && (idx > - 1) ? true : false;
    }
    return retVal
}

async function isBankAccountForUser(req: Request, accountId: string): Promise<boolean> {
    let retVal: boolean = false;
    if (authService != null && process.env?.NO_AUTH_SERVER?.toUpperCase() == "TRUE") {
        let idx = (await userService.getUser(req))?.accountsBanking?.findIndex((x: string) => accountId);
        retVal = (idx != null) && (idx > - 1) ? true : false;
    }
    return retVal
}

async function isEnergyAccountForUser(req: Request, accountId: string): Promise<boolean> {
    let retVal: boolean = false;
    if (authService != null && process.env?.NO_AUTH_SERVER ?.toUpperCase()== "TRUE") {
        let idx = (await userService.getUser(req))?.accountsEnergy?.findIndex((x: string) => accountId);
        retVal = (idx != null) && (idx > - 1) ? true : false;
    }
    return retVal
}

function validateQueryParameters(query: any, allowedParams: string[]): any {
    if (query == null)
        return;
    let errorList: any = {
        errors: []
    };
    for (const property in query) {
        if (allowedParams.indexOf(property) == -1) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid query parameter parameter: ${property}`, errorList);
        }
    }
    var pageSize = 25;
    // check pagination parmeters
    if (query["page-size"] != null && query["page-size"] != "") {
        pageSize = parseInt(query["page-size"]);
        if (isNaN(pageSize)) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid page-size parameter: ${pageSize}`, errorList)
        }
        else if (pageSize > 1000) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_PAGE_SIZE, `page-size ${pageSize} exceeds maximum`, errorList)
        }
    }
    if (query["page"] != null && query["page"] != "") {
        let page = parseInt(query["page"]);
        if (isNaN(page)) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid page parameter: ${query["page"]}`, errorList)
        }
    }
    // check date parameters
    var formats = [
        'YYYY-MM-DDTHH:mm:ss.sssssZ',
        'YYYY-MM-DDTHH:mm:ss.sssZ',
        'YYYY-MM-DDTHH:mm:ss-HH:mm'
    ];
    if (query["updated-since"] != null && query["updated-since"] != "") {
        let dateString = query["updated-since"];
        if (moment(dateString, formats, true).isValid() == false) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid updated-since parameter: ${dateString}`, errorList)
        }
    }
    if (query["oldest-date"] != null && query["oldest-date"] != "") {
        let dateString = query["oldest-date"];
        if (moment(dateString, formats, true).isValid() == false) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid oldest-date parameter: ${dateString}`, errorList)
        }
    }
    if (query["newest-date"] != null && query["newest-date"] != "") {
        let dateString = query["newest-date"];
        if (moment(dateString, formats, true).isValid() == false) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid newest-date parameter: ${dateString}`, errorList)
        }
    }
    if (query["oldest-time"] != null && query["oldest-time"] != "") {
        let dateString = query["oldest-time"];
        if (moment(dateString, formats, true).isValid() == false) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid oldest-time parameter: ${dateString}`, errorList)
        }
    }
    if (query["newest-time"] != null && query["newest-time"] != "") {
        let dateString = query["newest-time"];
        if (moment(dateString, formats, true).isValid() == false) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid newest-time parameter: ${dateString}`, errorList)
        }
    }
    // check open-staus
    if (query["open-status"] != null && query["open-status"] != "") {
        let validStates: string[] = ["OPEN", "CLOSED", "ALL"]
        if (validStates.indexOf(query["open-status"]) == -1) {
            errorList = buildErrorMessage(DsbStandardError.INVALID_FIELD, `Invalid open-satus parameter: ${query["open-status"]}`, errorList)
        }
    }
    if (errorList.errors.length > 0) {
        return errorList;
    }
    else
        return;
}

initaliseApp();

