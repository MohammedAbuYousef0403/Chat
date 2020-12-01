const mongoose = require('mongoose')
const jwt      = require('jsonwebtoken')
const bcrypt   = require('bcrypt')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        maxlength: 20
    },
    username: {
        type: String,
        required: true,
        unique: true,
        maxlength: 20
    },
    password: {
        type: String,
        required: true
    },
    about: {
        type: String,
        maxlength: 100
    },
    avatar: String,
})

/**
 * Pre save middleware (before save user document).
 * @param next
 */
UserSchema.pre('save', function(next) {
    if(this.isNew || this.isModified('password')){
        this.password = bcrypt.hashSync(this.password, 8)
    }
    next()
})

/**
 * Get user profile data.
 */
UserSchema.methods.getData = function(){
    return {
        id: this._id,
        name: this.name,
        username: this.username,
        about: this.about,
        avatar: this.avatar
    }
}

/**
 * Generate user token with profile data.
 */
UserSchema.methods.signJwt = function(){
    let data = this.getData()
    data.token = jwt.sign(data, process.env.JWT_SECRET)
    return data
}

/**
 * Check if given password is correct.
 * @param password
 */
UserSchema.methods.checkPassword = function(password) {
    return bcrypt.compareSync(password, this.password)
}

/**
 * Append id attribute.
 */
UserSchema.virtual('id').get(function(){
    return this._id.toHexString()
})

/**
 * Enable virtual attributes (id).
 */
UserSchema.set('toJSON', {
    virtuals: true
})

module.exports = mongoose.model('User', UserSchema)
