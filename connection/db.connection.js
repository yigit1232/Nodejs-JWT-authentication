const mongoose = require('mongoose')

mongoose.connect('mongodb://127.0.0.1:27017/app')
.then(result=>{
    console.log('connected to db')
})
.catch(e=>{
    console.log(e)
})