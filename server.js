import { Hono } from 'hono';
import bcrypt from 'bcrypt';
import Joi from 'joi';
import { Sequelize, DataTypes } from 'sequelize';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import { serveStatic } from '@hono/node-server/serve-static';
import session from 'hono-session';
import { json } from 'hono/json';

const app = new Hono();

const port = 5000;
const ip = '192.168.100.12';

app.use('/static/*', serveStatic({ root: './public' }));

app.use('*', json());

app.use('*', session({
  cookie: {
    name: 'session',
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60, // 1 hour
  },
  secret: '2.3m4tb62.46m23.54mn7v35.h56483jn12u35g12uy35g2iut3jyn3ik5hjyby356j7u46.sgsfujhgsa8gy84w423k.adsfgsa43y3w2qgsfdzg-6v846v4ipgt0-32gn32v32.4gnml.345np24t23.4tn32.45bn73;5o74j5[y3,5my35mn',
}));

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'database.sqlite'),
  logging: false
});

const User = sequelize.define('User', {
  firstName: { type: DataTypes.STRING, allowNull: false },
  lastName: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  nickname: { type: DataTypes.STRING, allowNull: false, unique: true },
  birthdate: { type: DataTypes.DATE, allowNull: false },
  role: { type: DataTypes.STRING, allowNull: false, defaultValue: 'user' },
  profilePicture: { type: DataTypes.STRING, allowNull: false, defaultValue: '/uploads/profile-pics/default-profile.png' }
}, {
  timestamps: true,
});

sequelize.sync({ alter: true });

const userSchema = Joi.object({
  firstName: Joi.string().min(2).max(30).required(),
  lastName: Joi.string().min(2).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
  nickname: Joi.string().min(3).max(30).required(),
  birthdate: Joi.date().required(),
  role: Joi.string().valid('owner', 'admin', 'artist', 'user').default('user')
});

app.post('/api/register', async (c) => {
  const { error, value } = userSchema.validate(await c.req.json());
  if (error) {
    return c.json({ message: error.details[0].message }, 400);
  }

  const { firstName, lastName, email, password, nickname, birthdate } = value;

  const age = new Date().getFullYear() - new Date(birthdate).getFullYear();
  if (age < 12) {
    return c.json({ message: 'Musisz mieć co najmniej 12 lat, aby założyć konto.' }, 400);
  }

  const existingUser = await User.findOne({ where: { nickname } });
  if (existingUser) {
    return c.json({ message: 'Pseudonim jest już zajęty.' }, 400);
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const userCount = await User.count();
    const role = userCount === 0 ? 'owner' : 'user';

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      nickname,
      birthdate,
      role,
    });

    const sessionUser = {
      id: newUser.id,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      nickname: newUser.nickname,
      role: newUser.role,
      profilePicture: newUser.profilePicture,
    };

    await c.session.set('user', sessionUser);

    return c.json({
      message: 'Rejestracja udana. Zostałeś zalogowany.',
      user: sessionUser,
    }, 201);
  } catch (err) {
    console.error('Błąd podczas rejestracji:', err);
    return c.json({ message: 'Wystąpił błąd podczas rejestracji.' }, 500);
  }
});

const isAuthenticated = async (c, next) => {
  const user = await c.session.get('user');
  if (user) {
    c.user = user;
    await next();
  } else {
    return c.redirect('/');
  }
};

const redirectIfAuthenticated = async (c, next) => {
  const user = await c.session.get('user');
  if (user) {
    return c.redirect('/');
  }
  await next();
};

const isOwner = async (c, next) => {
  const user = await c.session.get('user');
  if (user && user.role === 'owner') {
    await next();
  } else {
    return c.redirect('/noaccess');
  }
};

const isAdminOrOwner = async (c, next) => {
  const user = await c.session.get('user');
  if (user && (user.role === 'admin' || user.role === 'owner')) {
    await next();
  } else {
    return c.redirect('/noaccess');
  }
};

const isOwnerOrArtist = async (c, next) => {
  const user = await c.session.get('user');
  if (user && (user.role === 'owner' || user.role === 'artist')) {
    await next();
  } else {
    return c.redirect('/noaccess');
  }
};

app.get('/dev/api/access/admin/adminPanel', isAdminOrOwner, async (c) => {
  return c.render('./admin/adminpanel', { user: c.user });
});

app.get('/dev/api/access/admin/ownerPanel', isOwner, async (c) => {
  return c.render('./owner/ownerpanel', { user: c.user });
});

app.post('/api/login', async (c) => {
  const { email, password } = await c.req.json();

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      console.error('Użytkownik nie znaleziony dla email:', email);
      return c.json({ message: 'Nieprawidłowy email lub hasło.' }, 400);
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      console.error('Niepoprawne hasło dla użytkownika:', user.email);
      return c.json({ message: 'Nieprawidłowy email lub hasło.' }, 400);
    }

    const sessionUser = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      nickname: user.nickname,
      role: user.role,
      profilePicture: user.profilePicture,
    };

    await c.session.set('user', sessionUser);

    return c.json({ message: 'Logowanie udane.' });
  } catch (error) {
    console.error('Błąd logowania:', error);
    return c.json({ message: 'Wystąpił błąd na serwerze.' }, 500);
  }
});

app.post('/api/logout', async (c) => {
  await c.session.delete();
  return c.json({ message: 'Wylogowano pomyślnie.' });
});

app.get('/api/users', isAuthenticated, async (c) => {
  const query = c.req.query('query');

  try {
    let users;

    if (query) {
      users = await User.findAll({
        where: {
          [Sequelize.Op.or]: [
            { nickname: { [Sequelize.Op.like]: `%${query}%` } },
            { email: { [Sequelize.Op.like]: `%${query}%` } }
          ]
        },
        order: [['nickname', 'ASC']]
      });
    } else {
      users = await User.findAll({
        order: [['nickname', 'ASC']]
      });
    }

    return c.json(users);
  } catch (err) {
    console.error('Błąd podczas pobierania użytkowników:', err);
    return c.json({ message: 'Wystąpił błąd podczas pobierania użytkowników.' }, 500);
  }
});

app.get('/api/all-users', isOwner, async (c) => {
  const query = c.req.query('query');

  try {
    let users;

    if (query) {
      users = await User.findAll({
        where: {
          [Sequelize.Op.or]: [
            { nickname: { [Sequelize.Op.like]: `%${query}%` } },
            { email: { [Sequelize.Op.like]: `%${query}%` } }
          ]
        },
        order: [['nickname', 'ASC']]
      });
    } else {
      users = await User.findAll({
        order: [['nickname', 'ASC']]
      });
    }

    return c.json(users);
  } catch (err) {
    console.error('Błąd podczas pobierania wszystkich użytkowników:', err);
    return c.json({ message: 'Wystąpił błąd podczas pobierania wszystkich użytkowników.' }, 500);
  }
});

const storage = multer.diskStorage({
  destination: './public/uploads/profile-pics/',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ storage });

app.post('/api/upload-profile-pic', isAuthenticated, upload.single('profilePic'), async (c) => {
  const file = c.req.file;

  if (!file) {
    return c.json({ message: 'Nie przesłano żadnego pliku.' }, 400);
  }

  const filePath = `/uploads/profile-pics/${file.filename}`;

  try {
    const user = await User.findByPk(c.user.id);

    if (!user) {
      return c.json({ message: 'Użytkownik nie został znaleziony.' }, 404);
    }

    user.profilePicture = filePath;
    await user.save();

    return c.json({
      message: 'Zdjęcie profilowe zostało przesłane.',
      profilePicture: filePath,
    });
  } catch (error) {
    console.error('Błąd podczas przesyłania zdjęcia profilowego:', error);
    return c.json({ message: 'Wystąpił błąd podczas przesyłania zdjęcia profilowego.' }, 500);
  }
});

app.listen(port, () => {
  console.log(`Server is running at http://${ip}:${port}`);
});
