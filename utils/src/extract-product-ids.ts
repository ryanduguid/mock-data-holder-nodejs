/* Created for testing purposes. 
    In order to test generated data from test cli the postman collections from dsb-postman can be used
    in a collection runner, iterating over product ids.

    This will test the randamly generated data
*/

import { readFileSync, writeFileSync } from 'fs';
import path from 'path';

const bankingProductsFile = path.join(__dirname, '/data/banking-products-output.json')
const productIdOutputFile = path.join(__dirname, '/data/out/banking-product-ids.json')

const sourceData: any = JSON.parse(readFileSync(bankingProductsFile, 'utf8'));

let holders = sourceData?.holders;
let prodIds: any[] = [];

holders?.forEach((h: any) => {
    let products = h.holder?.unauthenticated?.banking?.products;
    products?.forEach((p: any) => {
        let id = p?.productId;
        if (id != null) {
            let obj = {
                prductId: `${id}`
            }
            prodIds.push(obj);
        }        
    })
});

if (prodIds.length > 0) {
    writeFileSync(productIdOutputFile, JSON.stringify(prodIds, null, 2));
}

