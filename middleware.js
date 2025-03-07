const jwt = require('jsonwebtoken');
const { User, Role } = require('./models/UsersModel');
const BlacklistedToken = require('./models/BlacklistedTokenModel');

const authenticateToken = async (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(403).json({message: 'Access Denied'});

    const blacklistedToken = await BlacklistedToken.findOne({where: {token}});
    if (blacklistedToken) {
        return res.status(403).json({message: 'Token is blacklisted'});
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.status(403).json({message: 'Invalid Token'});

        const user = await User.findByPk(decoded.id);
        if (!user) return res.status(403).json({message: 'User not found'});

        req.user = {id: user.id};
        next();
    });
}

    const checkAdmin = async (req, res, next) => {
        try {
            const user = await User.findByPk(req.user.id, {
                include: {model: Role, attributes: ['name']}
            });

            if (!user || !user.Roles.some(role => role.name === 'admin')) {
                return res.status(403).json({message: 'Admin access required'});
            }

            next();
        } catch (error) {
            res.status(500).json({message: 'Error checking admin role', error: error.message});
        }
    };


module.exports = { authenticateToken, checkAdmin };
