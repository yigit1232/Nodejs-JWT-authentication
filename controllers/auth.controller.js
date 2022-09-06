const User = require('../models/user.model')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const login = async (req,res) => {
    try{
        const {username,password} = req.body
        if(!username || !password){
            return res.status(400).json({message:'please enter all fields'})
        }
        const user = await User.findOne({username})
        if(user){
            const match = await bcrypt.compare(password,user.password)
            if(match){
                const token = await jwt.sign({
                    id:user._id,
                    username:user.username,
                    email:user.email,
                    name:user.name
                },'secretKey',{expiresIn:'2h'})
                return res.status(200).json({message:'Success',token:token})
            } else{
                return res.status(400).json({message:'Username or password is incorrect'})
            }
        }else{
            return res.status(400).json({message:'Username or password is incorrect'})
        }
    }catch(e){
        res.status(500).json(e)
    }
}

const register = async (req,res) => {
   try{
        const {username,name,email,password,againPassword} = req.body
        if(password !== againPassword){
            return res.status(400).json({message:'passwords do not match'})
        }
        if(!username || !name || !email || !password || !againPassword){
            return res.status(400).json({message:'please enter all fields'})
        }
        const isMail = await User.findOne({email})
        if(isMail){
            return res.status(400).json({message:'email already exists'})
        }
        const isUsername = await User.findOne({username})
        if(isUsername){
            return res.status(400).json({message:'username already exists'})
        }
        const hashedPassword = await bcrypt.hash(password,10)
        const user = new User({
            username:username,
            name:name,
            email:email,
            password:hashedPassword
        })
        if(user){
            await user.save()
            return res.status(201).json(user)
        }else{
            return res.status(400).json({message:'user not created'})
        }
   }catch(e){
         res.status(500).json(e)
   }
}

module.exports = {register,login}