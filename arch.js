const crypto = require('crypto');
const algorithm = 'aes-192-cbc';
const password = 'my password';
const fPromise = require('fs').promises

let key;
let iv;


/*generate a random buffer - init vector*/
  /*@ the Obj must contain some neccessary properties:
  .path (path to thte file for writing)
  .alg (name of algorithm)
  .psw  (password)
  .plainText (plain text for encoding)
  */
async function prepareIV (obj) {
  
  return await new Promise((resolve,reject)=>{
    /*create an initialization vector*/
    crypto.randomFill(new Uint8Array(16),(err, iv)=>{
      if (err) {
        reject(err);
      } else {
        obj.iv = iv;
        console.log('1');
        resolve(obj);
      }
    })      
  })

}

async function makeKey (obj) {
  return await new Promise((resolve,reject)=>{
    crypto.scrypt(obj.psw,'salt',24,(err,key)=>{
      if (err) { reject(err) }
      else {
        obj.key = key;
        resolve(obj);
      }
    })

  })
}

async function makeCrypted (obj) {
  return await new Promise( (resolve,reject)=>{
      let cipher = crypto.createCipheriv(obj.alg, obj.key, obj.iv);
      /*set HEX encoding*/
      cipher.setEncoding('hex');
      let encrypted = '';
      /*when readable event of stream - write result to a buffer*/
      cipher.on('readable',()=>{
        let chunk;
         while (null !== (chunk = cipher.read())) {
              encrypted += chunk;
         }
      })
      /*after end - convert results and resolve*/
      cipher.on('end',()=>{
          obj.encrypted = encrypted;
          resolve(obj);
      })
      /*write plain text into cipheriv instance
      and start process*/
      cipher.write(obj.plainText)
      cipher.end();  
  })
}

async function writeResult (obj) {
  return await new Promise((resolve,reject)=>{
    let msg = Buffer.from(obj.iv);
    msg = msg.toString('hex');
    console.log('CIPHER: '+obj.encrypted);
    msg += obj.encrypted;
    fPromise.writeFile(obj.path,msg,{flag:'w'})
    .then(()=>{
      console.info('done!');
      resolve();
    })
    .catch((q)=>reject(q))
  })
}

prepareIV({psw:'my password',path:'2.sec',alg:'aes-192-cbc',plainText:"Heelou word"})
.then(makeKey)
.then(makeCrypted)
.then(writeResult)
.then((obj)=>{
  console.log(obj);
})

/********************D E C I P H E R********************************** */
const crypto = require('crypto')

const fsPromise = require('fs').promises
const passw = 'my password'
/*an obj must have 
properties:
.path = (file name)
.psw (password)
.alg (name of the algorithm)
*/
async function readInfo(obj){
  /*try to open a file*/
  return await new Promise ((resolve,reject)=>{
     fsPromise.readFile(obj.path)
     .then((buf)=>{
       obj.iv = buf.slice(0,32).toString();
       obj.iv = Buffer.from(obj.iv,'hex');
       obj.encrypted = buf.slice(32).toString('utf8');
       console.log(obj.iv);
       console.log(obj.encrypted);
       resolve(obj);
     })
     .catch((w) => reject(q))
  })
}
/*generatin a key by password*/
async function keyGen (obj) {
   return new Promise ((resolve,reject)=>{
     crypto.scrypt(obj.psw,'salt',24,(err,key)=>{
       if (err) {reject(err)}
       else {
         obj.key = key;
         console.log('1');
         resolve(obj);
       }
     })
   })
}

/*decipher an info*/

async function decode (obj) {
  return new Promise((resolve,reject)=>{
    let decrypt = crypto.createDecipheriv(obj.alg,obj.key,obj.iv);
    let decrypted = '';
    decrypt.on('readable',()=>{
        let tmp; 
        while(null !== (tmp = decrypt.read())) {
          decrypted += tmp.toString('utf8');
        }
    })
    decrypt.on('end',()=>{
      console.log('2');
      resolve(decrypted);
    })
    decrypt.on('error',(e)=>reject(e));
    /*pass an info into engine-and set an encoding*/
    decrypt.write(obj.encrypted,'hex');
    /*and start to decipher*/
    decrypt.end();
  })
}

readInfo({path:'2.sec',psw:passw,alg:'aes-192-cbc'})
.then(keyGen)
.then(decode)
.then((obj)=>{
  console.log(obj);
})
.catch((q)=>console.info('ERRRROR'+q));
