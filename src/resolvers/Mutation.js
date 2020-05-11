const bcrypt = require('bcryptjs');
const JWT = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');

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
    async signup(parent, args, ctx, info) {
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
    async signin(parent, { email, password }, ctx, info) {
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
    },
    async addToCart(parent, args, ctx, info) {
        //make sure they are logged in 
        const { userId } = ctx.request;
        if (!userId) {
            throw new Error('You must be logged in');
        }
        //query the user current cart 
        const [existingCartItem] = await ctx.db.query.cartItems({
            where: {
                user: {
                    id: userId
                },
                item: {
                    id: args.id
                }
            }

        });
        // check if that item already in that cart
        if (existingCartItem) {
            return ctx.db.mutation.updateCartItem({
                where: {
                    id: existingCartItem.id
                },
                data: {
                    quantity: existingCartItem.quantity + 1
                }
            }, info);
        }
        // create CartItem 
        return ctx.db.mutation.createCartItem({
            data: {
                user: {
                    connect: {
                        id: userId
                    }
                },
                item: {
                    connect: {
                        id: args.id
                    }
                }
            }
        }, info)
    },

    async removeFromCart(parent, args, ctx, info) {
        // find the cart item 
        const cartItem = await ctx.db.query.cartItem({
            where: {
                id: args.id
            }
        }, `{ id, user { id }}`);
        // make sure we found cart item 
        if (!cartItem) throw new Error('No CartItem found!');
        // make sure they own that cart item 
        if (cartItem.user.id !== ctx.request.userId) {
            throw new Error('Cheatin hahahha');
        }
        // delete that cart item 
        return ctx.db.mutation.deleteCartItem({
            where: {
                id: args.id
            }
        }, info);
    },

    async createOrder(parent, args, ctx, info) {
        // query the current user and make sure they are sign in 
        const {userId} = ctx.request;
        if (!userId) throw new Error('You must be signed in to complete this order');
        const user = await ctx.db.query.user({
            where: {
                id: userId
            }
        }, `{ id name email cart { id quantity item { title price id description image largeImage }} }`)
        // recalculate the total for the price 
        const amount = user.cart.reduce((tally, cartItem) => tally + cartItem.item.price * cartItem.quantity, 0);
        console.log('ddddd', amount);
        // create the stripe charge
        const charge = await stripe.charges.create({
            amount, 
            currency: 'USD', 
            source: args.token
        });
        // convert the CartItems to OrderItems 
        const orderItems = user.cart.map(cartItem => {
            const orderItem = {
                ...cartItem.item,
                quantity: cartItem.quantity,
                user: {
                    connect: { id: userId }
                }
            };
            delete orderItem.id;
            return orderItem;
        });
        // create the Order
        const order = await ctx.db.mutation.createOrder({
            data: {
                total: charge.amount,
                charge: charge.id,
                items: {
                    create: orderItems
                },
                user: {
                    connect: { id: userId }
                }
            }, 
        });
        // clean up  - clear the users cart, delete cartItems 
        const cartItemsIds = user.cart.map(cartItem => cartItem.id);
        await ctx.db.mutation.deleteManyCartItems({
            where: {
                id_in: cartItemsIds
            }
        });
        // return the order to the client
        return order;
    }

};

module.exports = Mutations;
