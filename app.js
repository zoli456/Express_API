const express = require('express');
const userRoutes = require('./routes/userRoutes');
const messageRoutes = require('./routes/messagesRoutes');
const adminRoutes = require('./routes/adminRoutes');
const { sequelize } = require('./models');
const {Role, User} = require("./models/UsersModel");
const app = express();
const audit = require('express-requests-logger');
const cron = require('node-cron');
const BlacklistedToken = require('./models/BlacklistedTokenModel');

app.use(express.json());

app.use(audit());

const bcrypt = require('bcryptjs');
const { Op } = require("sequelize");

const seedDatabase = async (seed) => {
  await sequelize.sync({ force: false });
  console.log('Database synced');

  if (!seed) return;
  try {
    const [adminRole] = await Role.findOrCreate({ where: { name: 'admin' } });
    const [userRole] = await Role.findOrCreate({ where: { name: 'user' } });

    const hashedPassword = await bcrypt.hash('adminpassword', 10);

    const adminUser = await User.create({
      username: 'admin',
      email: 'admin@hotmail.com',
      password: hashedPassword
    });

    // Assign roles to admin user
    await adminUser.addRoles([adminRole, userRole]);

    console.log('Seed data inserted');
  } catch (error) {
    console.error('Error seeding database:', error);
  }
};

module.exports = seedDatabase;

app.use('/api/users', userRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/admin', adminRoutes);

seedDatabase(false);

cron.schedule('0 0 * * *', async () => {
  try {
    await BlacklistedToken.destroy({ where: { expiresAt: { [Op.lt]: new Date() } } });
    console.log('Expired tokens deleted');
  } catch (error) {
    console.error('Error deleting expired tokens:', error);
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));