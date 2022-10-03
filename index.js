const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

let config = null;
let dbSchema = {created:{type:Date, default:Date.now}}
let UserSchema = null;
let userTable = null;
let db = null;

const setup = (userConfig = {}) => {
    return async (req, res, next) => {
        config = userConfig;
        let isValidConfig = await validateConfig(config)
        if(isValidConfig !== true) return res.status(403).json({msg: isValidConfig});
        try{
        db = mongoose.createConnection(config.mongoConnectionURI+config.mongoDbName, {useNewUrlParser: true, useUnifiedTopology: true});
        }catch(err){
            return (req, res, next) => {      
                return res.status(403).json({msg: 'Could not connect with mongodb!'});
            }
        }
        dbSchema[config.fileds.username] = { type:String, sparse:true, index:true }
        dbSchema[config.fileds.password] = { type:String }    
        dbSchema[config.fileds.authorizationRole] = { type:String }   
        UserSchema = mongoose.Schema(dbSchema);
        userTable = db.model(config.mongoAuthCollectionName,UserSchema);
        return next();
    }
}

const validateConfig = async (config) => {
    if(!config) return 'Missing auth setup!'
    if(!config.mongoConnectionURI) config['mongoConnectionURI'] = 'mongodb://localhost:27017/';
    if(!config.mongoDbName)  return 'Missing config: mongoDbName';
    if(!config.mongoAuthCollectionName) config['mongoAuthCollectionName'] = 'users';
    if(!config.fileds) config['fileds'] = { username: 'email', password: 'password' };
    if(!config.fileds.username) config['fileds']['username'] = 'email';
    if(!config.fileds.password) config['fileds']['password'] = 'password';
    if(!config.roleBasedAuthorization) config['roleBasedAuthorization'] = false;
    if(!config.authToken) config['authToken'] = { fileds: '[*]', expiresIn: '1h' };
    if(!config.authToken.fileds) config['authToken']['fileds'] = '[*]';
    if(!config.authToken.expiresIn) config['authToken']['expiresIn'] = '1h';
    if(!config.passwordSaltRound) config['passwordSaltRound'] = 8;
    if(config.passwordSaltRound>10) config.passwordSaltRound = 10;
    if(config.passwordSaltRound<2) config.passwordSaltRound = 2;
    return true;
}

const register = async (req, resp, next) => {
    let isValidConfig = await validateConfig(config)
    if(isValidConfig !== true) return resp.status(403).json({msg: isValidConfig});    
    if(!req.body[config.fileds.username]) return resp.status(403).json({msg: 'Missing field ->  '+config.fileds.username});    
    if(!req.body[config.fileds.password]) return resp.status(403).json({msg: 'Missing field ->  '+config.fileds.password});
    if(config.roleBasedAuthorization){
        if(!req.body[config.fileds.authorizationRole]) return resp.status(403).json({msg: 'Missing field -> '+config.fileds.authorizationRole});
    }    
    let filter = {};
    filter[config['fileds']['username']] = req.body[config.fileds.username];    
    let info = await userTable.findOne(filter); if(info) return resp.status(403).json({msg: 'User is already registered!'});       
    let value = {};
    value[config['fileds']['username']] = req.body[config.fileds.username];
    value[config['fileds']['password']] = await generateHash(req.body[config.fileds.password]);
    value[config['fileds']['authorizationRole']] = req.body[config.fileds.authorizationRole];
    let user = await userTable.create(value); if(!user) return resp.status(403).json({msg: 'User registration failed!'});  
    req.newUser = user;         // client will have to check this for registration 
    return next()
}

const authenticate = async (req, resp, next) => {
    let isValidConfig = await validateConfig(config)
    if(isValidConfig !== true) return resp.status(403).json({msg: isValidConfig});
    if(!req.body[config.fileds.username]) return resp.status(403).json({msg: 'Missing '+config.fileds.username});    
    if(!req.body[config.fileds.password]) return resp.status(403).json({msg: 'Missing '+config.fileds.password});    
    let filter = {};
    filter[config['fileds']['username']] = req.body[config.fileds.username];
    let info = await userTable.findOne(filter).lean(); if(!info) return resp.status(403).json({msg: 'Not registered!'});
    if(!await compareHash(req.body[config.fileds.password] , info[config['fileds']['password']]))
         return resp.status(403).json({msg: 'Invalid credentials!'});

    let tokenObj = info;   
    if(config.authToken.fileds[0] !== '*'){
        tokenObj = {}
        config.authToken.fileds.forEach((el,i)=>{
            tokenObj[el] = info[el]
        })
    }   
    info['authToken'] = await generateJWT(tokenObj, config.authToken.expiresIn)
    req.user = info;
    return next()
}

const authorize = async (req, res, next) => {
    let isValidConfig = await validateConfig(config)
    if(isValidConfig !== true) return res.status(403).json({msg: isValidConfig});
    if(!config)  return res.status(403).json({msg: 'Missing auth setup!'});
    if(!req.headers.authorization) return res.status(401).json({msg: 'Unauthorized'}); 
    let token = req.headers.authorization.split(' ')[1];
    let info = await verifyJWT(token);
    if(!info) return res.status(401).json({msg: 'Unauthorized'}); 
    let filter = {};
    filter[config['fileds']['username']] = info[config.fileds.username];  
    let authUser = await userTable.findOne(filter);
        if(!authUser) return res.status(401).json({msg: 'Unauthorized'}); 
    req.user = authUser; 
    return next()
}

const authorizeRole = (...roles) => {
    return async (req, res, next) => {
        try {
         if(!req.user || !roles) return res.status(401).json({msg: 'Unauthorized'}); 
         if(!req.user[config['fileds']['authorizationRole']]) return res.status(401).json({msg: 'Role setup incomplete!'});
         if(!Array.isArray(roles)) roles = [roles];
         if(roles.indexOf(req.user[config['fileds']['authorizationRole']]) <0) return res.status(401).json({msg: 'Access Denied!'});
         return next()
        } catch (error) {return res.status(401).json({msg: 'Role setup incomplete!'}); }
    }
}

const generateJWT = async (value, expiresIn = '72h') => { return jwt.sign(value, process.env.JWT_KEY, { expiresIn: expiresIn }); }
const verifyJWT = async (authToken) => {  try{ return jwt.verify(authToken, process.env.JWT_KEY); }catch(err){ return false; } }
const generateHash = async (val) => {
    const saltRounds = config['passwordSaltRound'];
    try{
        return await bcrypt.hash(val, saltRounds)
    }catch(err){ return false }
}

const compareHash = async (value, hash) => {
    try{
        if(!await bcrypt.compare(value, hash)) return false;        
        return true;
    }catch(err){ return false }
}

module.exports = {
    setup: setup,
    register: register,
    authenticate: authenticate,
    authorize: authorize,
    authorizeRole: authorizeRole
}


// sample config
// let config = {                                               
//     mongoConnectionURI: 'mongodb://localhost:27017/',               // default -> mongodb://localhost:27017/
//     mongoDbName: 'anewdb',                                          // * mandatory
//     mongoAuthCollectionName: 'user_collection',                     // default -> users
//     fileds: {                                                       // default fileds -> email, password
//         username: 'username',
//         password: 'secret',
//         authorizationRole: 'role'
//     },
//     passwordSaltRound: 5,                                           // range -> 2 to 10,  default -> 8  
//     roleBasedAuthorization: true,                                   // default -> false
//     authToken: {                                                    // default authToken -> ['*'], 1h
//         fileds: ['username','bla','blaa'],              
//         expiresIn: '1h',
//     }
// }
