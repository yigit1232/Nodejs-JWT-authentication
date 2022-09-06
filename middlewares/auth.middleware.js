const jwt = require('jsonwebtoken')

const authMiddleware = (req,res,next) => {
    try{
        const token = req.headers.authorization.split(' ')[1]
        if(token){
             const decoded = jwt.verify(token,'secretKey')
             req.userData = decoded
        next()
        }else{
            next()
        }
    }catch(e){
        res.status(500).json(e)
    }
}
module.exports = authMiddleware
