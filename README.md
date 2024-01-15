## How to use the middleware?
```
const authModule = require('./index');

router.use(authModule.setup({                                       // available setup configurations
    mongoConnectionURI: 'mongodb://localhost:27017/',               // default -> mongodb://localhost:27017/
    mongoDbName: 'anewdb1',                                          // * mandatory
    mongoAuthCollectionName: 'userTable',                           // default -> users
    fileds: {                                                       // default fileds -> email, password
        username: 'email',
        password: 'secret',
        authorizationRole: 'role'
    },
    passwordSaltRound: 6,                                           // range -> 2 to 10,  default -> 8  
    roleBasedAuthorization: true,                                   // default -> false
    authToken: {                                                    // default authToken -> ['*'], 1h
        fileds: ['email','bla','blaa'],              
        expiresIn: '1h',
    }
}))

// router.use(authModule.setup({                               // minimal setup
//     mongoDbName: 'xyzdb',
// }), (req, res) => {})


router.post('/create', authModule.register, (req, res) => {
    if(!req.newUser) return res.status(403).json({msg: 'Unable to create new user!'});

    // do other stuffs with the collection if required
    // ----------------------------------------------

    return res.status(200).json({'message': 'User registered successfully!'})
})

router.post('/authenticate', authModule.authenticate, (req, res) => {
    if(!req.user) return res.status(403).json({msg: 'Invalid credentials!'});
    
    // do other stuffs if required
    // --------------------------

    return res.status(200).json(req.user)
})

router.get('/user-info', authModule.authorize, (req, res) => {   

    // do other stuffs if required
    // --------------------------

    return res.status(200).json(req.user)
})

router.get('/check-role', authModule.authorize, authModule.authorizeRole('customer','admin','dskjfk') , (req, res) => {   

    // do other stuffs if required
    // --------------------------

    return res.status(200).json(req.user)
})
```
