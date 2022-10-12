const xsenv = require('@sap/xsenv')
const serviceBindings = xsenv.getServices({ 
   myXsuaa: {tag: 'xsuaa'}
})
const UAA_CREDENTIALS = serviceBindings.myXsuaa
const DATABASE = new Array() // Global variable representing database

const express = require('express')
const app = express()
const xssec = require('@sap/xssec')
const passport = require('passport')
const JWTStrategy = xssec.JWTStrategy
passport.use('JWT', new JWTStrategy(UAA_CREDENTIALS))
app.use(passport.initialize())
app.use(passport.authenticate('JWT', {session: false}))
app.use(express.json())
app.use(logJwtMiddle)


/* App server */
app.listen(process.env.PORT)


/* Middleware */
function logJwtMiddle (req, res, next) {
   const tokenEncoded = req.headers["authorization"].substring(7)
   let jwtBase64Encoded = tokenEncoded.split('.')[1]
   let jwtDecodedAsString = Buffer.from(jwtBase64Encoded, 'base64').toString('ascii')
   let jwtDecoded = JSON.parse(jwtDecodedAsString)

   console.log(`===> The full JWT decoded: ${JSON.stringify(jwtDecoded)}`) 
   console.log(`==> JWT scope: ${jwtDecoded.scope}`)
   console.log(`==> JWT role collections: ${JSON.stringify(jwtDecoded['xs.system.attributes'])}`)
   console.log(`==> JWT user attributes: ${JSON.stringify(jwtDecoded['xs.user.attributes'])}`)
   next()
}


/* App endpoints */
app.post('/create', (req, res) => {
   const auth = req.authInfo
   if (! auth.checkScope(UAA_CREDENTIALS.xsappname + '.scopeforcreate')) {
      res.status(403).end('Forbidden. Missing authorization for create.')
   }else{
      const body = req.body
      DATABASE.push({name: body.name, country: body.country})
      res.send(`Employee name: '${body.name}', country: '${body.country}'`)
   }
})

app.put('/manage', (req, res) => {
   const auth = req.authInfo
   const employeeName = req.body.name  
   const employeeEntry = DATABASE.find(e => e.name == employeeName)
   if(employeeEntry === undefined){
      res.status(404).end(`Employee '${employeeName}' not found.`)
   }
   const employeeCountry = employeeEntry.country      

   // authorization checks: manager is always entitled. Assistant is entitled only if in same country
   if (auth.checkScope(UAA_CREDENTIALS.xsappname + '.scopeformanage')) {
      res.send(`Salary increased for employee: '${employeeName}' by manager '${auth.getGivenName()}' .`)
   }else if(auth.checkScope(UAA_CREDENTIALS.xsappname + '.scopeforcreate')){
      const jwtDecoded = req.tokenInfo.getPayload()
      const userAttrCountry = jwtDecoded['xs.user.attributes'].Country 
      if(userAttrCountry == employeeCountry){
         res.send(`Salary increased for employee: '${employeeName}' by assistant '${auth.getGivenName()}' .`)
      }else{
         res.status(403).end(`User ${auth.getGivenName()} (${userAttrCountry}) not allowed to manage ${employeeName} (${employeeCountry}) due to different country.`)
      }
   }else{
      res.status(403).end('Forbidden. Missing authorization for managing employee.')
   }
})