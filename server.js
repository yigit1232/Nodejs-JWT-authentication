const express = require('express')
const app = express()
const port = 3000
const router = require('./router/auth.router')
const authMiddleware = require('./middlewares/auth.middleware')
require('./connection/db.connection')
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(authMiddleware)
app.use('/api',router)
app.listen(port,() =>{
    console.log(`http://localhost:${port}`)
})