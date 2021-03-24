const bcrypt = require('bcryptjs');

module.exports = {
    register: async (req, res) => {
        // BRING IN DATABASE
        const db = req.app.get('db');

        // RECEIVE NEEDED INFO TO EVENTUALLY ADD A NEW USER
        const {name, email, password, admin} = req.body;

        // CHECK IF AN EXISTING USER MATCHES EMAIL TRYING TO BE REGISTERED, IF SO REJECT
        try {
            const [existingUser] = await db.get_user_by_email(email)

            if (existingUser) {
                return res.status(409).send('User already exists')
            }

        // HASH AND SALT THE PASSWORD
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);

        // ADD USER TO DATABASE AND GET BACK THEIR ID
        const [newUser] = await db.register_user(name, email, hash, admin);

        // CREATE A SESSION FOR THE USER USING THE DATABASE RESPONSE
        req.session.user = newUser;

        // SEND A RESPONSE THAT INCLUDES THE USER SESSION INFO
        res.status(200).send(newUser);

        } catch(err) {
            console.log(err)
            return res.sendStatus(500)
        }
    },

    login: (req, res) => {
        // GET DATABASE INSTANCE
        const db = req.app('db');

        // GET NECESSARY INFO FROM REQ.BODY
        const {email, password} = req.body;

        // CHECK IF THAT USER EXISTS, IF THEY DO NOT REJECT REQUEST
        db.get_user_by_email(email)
            .then(([existingUser]) => {
                if (!existingUser) {
                    return res.status(403).send('Incorrect Email')
                }
                // COMPARE THE PASSWORD FROM REQ.BODY WITH THE STORED HASH THAT WE JUST RETRIEVED...IF MISMATCH REJECT
                const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)

                if (!isAuthenticated) {
                    return res.status(403).send('Incorrect Password')
                }
                // SET UP OUR SESSION AND BE SURE TO NOT INCLUDE THE HASH IN THE SESSION
                delete existingUser.hash;

                req.session.user = existingUser;

                // SEND THE RESPONSE AND SESSION TO THE FRONT
                res.status(200).send(req.session.user)
            })
    },

    logout: (req, res) => {
        req.session.destroy();
        res.sendStatus(200);
    },
}