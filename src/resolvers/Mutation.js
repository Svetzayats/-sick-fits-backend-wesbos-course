const bcrypt = require('bcryptjs'); 
const JWT = require('jsonwebtoken');
const { randomBytes} = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');

const Mutations = {
    async createItem(parent, args, ctx, info) {
        if (!ctx.request.userId) {
            throw new Error('You must be logged in to do that!');
        }
        //todo: check if they are logged in
        const item = await ctx.db.mutation.createItem({
            data: {
                //this is how we create relationship between the Item and User 
                user: {
                    connect: {
                        id: ctx.request.userId
                    }
                },
                ...args
            }
        }, info);
        return item;
    },
    updateItem(parent, args, ctx, info) {
        //first take a copy of the updates 
        const updates = { ...args };
        //remove the ID from the updates, его не нужно обновлять 
        delete updates.id;
        // run the update method 
        return ctx.db.mutation.updateItem({
            data: updates,
            where: {
                id: args.id
            }
        }, info);
    },
    async deleteItem(parent, args, ctx, info) {
        const where = { id: args.id };
        //1. find the item 
        const item = await ctx.db.query.item({ where }, `{ id title user {id} }`);
        //2. check the permissions
        const ownsItem = item.user.id === ctx.request.userId;
        const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission));
        if (!ownsItem && !hasPermissions) {
            throw new Error('You dont have permissions to do that');
        } 
        //3. delete it 
        return ctx.db.mutation.deleteItem({ where }, info);
    },
    async signup (parent, args, ctx, info) {
        args.email = args.email.toLowerCase();
        //hash the password
        const password = await bcrypt.hash(args.password, 10);
        //create the use in database 
        const user = await ctx.db.mutation.createUser({
            data: {
                ...args,
                password,
                permissions: { set: ['USER'] }
            }
        }, info);
        //create the JWT token for them
        const token = JWT.sign({
            userId: user.id
        }, process.env.APP_SECRET);
        //set the JWT as a cookie on the response
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365
        });
        return user;
    },
    async signin(parent, {email, password}, ctx, info) {
        //check if there is a user with that email 
        const user = await ctx.db.query.user({
            where: { email }
        });
        if (!user) {
            throw new Error(`No such user found for email ${email}`);
        }
        //check if their password is correct 
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
             throw new Error('Invalid Password');
        }
        //generate the JWT Token 
        const token = JWT.sign({
            userId: user.id
        }, process.env.APP_SECRET);
        //set the cookie with the token
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365
        });
        //return the user 
        return user;
    },
    signout(parent, args, ctx, info) {
        ctx.response.clearCookie('token');
        return {
            message: 'GoodBye!'
        }
    },
    async requestReset(parent, args, ctx, info) {
        //check if this is a real user 
        const user = await ctx.db.query.user({
            where: { email: args.email }
        });
        if (!user) {
            throw new Error(`No such user found for email ${args.email}`)
        }
        //set reset token and exprity on that user
        const randomBytesPromisified = promisify(randomBytes);
        const resetToken = (await randomBytesPromisified(20)).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;
        const res = await ctx.db.mutation.updateUser({
            where: {
                email: args.email
            },
            data: {
                resetToken,
                resetTokenExpiry
            }
        });        
        //email them that reset token
        const mailResponse = await transport.sendMail({
            from: 'mail@mail.ru',
            to: user.email,
            subject: 'Your password reset token',
            html: makeANiceEmail(
                `Your Password Reset Token is here! 
                \n\n 
                <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click here to reset</a>`
                )
        });

        return {
            message: 'Thanks'
        }
    },
    async resetPassword(parent, args, ctx, info) {
        //check if the passwords match
        if (args.password !== args.confirmPassword) {
            throw new Error('Passwords do not match!');
        }
        //check if its a legit reset token 
        //check if it its expires
        const [user] = await ctx.db.query.users({
            where: {
                resetToken: args.resetToken,
                resetTokenExpiry_gte: Date.now() - 3600000
            }
        });
        if (!user) {
            throw new Error('This token is either invalid or expired!');
        }
        //hash their new password
        const password = await bcrypt.hash(args.password, 10);
        //save the new password and remove old restToken
        const updateUser = await ctx.db.mutation.updateUser({
            where: {
                email: user.email
            },
            data: {
                password, 
                resetToken: null,
                resetTokenExpiry: null
            }
        });
        //generate JWT
        const token = JWT.sign({
            userId: updateUser.id
        }, process.env.APP_SECRET)
        //set the JWT cookie
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365
        })
        //return the new user 
        return updateUser;
    },
    async updatePermissions(parent, args, ctx, info) {
        //check if the are logged in 
        if (!ctx.request.userId) {
            throw new Error('You must be logged in');
        }
        //query the current user
        const currentUser = await ctx.db.query.user({
            where: {
                id: ctx.request.userId
            }
        }, info);
        //check if they have permission to do this
        hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
        //update the permissions
        return ctx.db.mutation.updateUser({
            data: {
                permissions: {
                    //because permissions is enum, we use set
                    set: args.permissions
                }
            },
            where: {
                id: args.userId
            }
        }, info);
    }

 };

module.exports = Mutations;
