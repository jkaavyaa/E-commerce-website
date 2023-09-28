const express = require('express');
const app = express();
const port = 4000;

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const serviceAccount = require('./key.json');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');

const bcrypt = require('bcrypt');

initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();

app.use(bodyParser.urlencoded({ extended: true }));
const sessionSecret = crypto.randomBytes(64).toString('hex');


// Set up session middleware
app.use(
  session({
    secret: sessionSecret, 
    resave: false,
    saveUninitialized: true,
  })
);

app.set('view engine', 'ejs');
app.use(express.static('public'));

app.get('/', (req, res) => {
  const user = req.session.user;
  if (user) {
    res.render('pages/dashboard', { user });
  } else {
    res.redirect('/login');
  }
});

app.get('/sign_up', (req, res) => {
  res.render('pages/sign_up');
});

app.post('/signupsubmit', async (req, res) => {
    const Fullname = req.body.Fullname;
    const Email = req.body.Email;
    const Password = req.body.Password;
  
    try {
      const emailExists = await checkEmailExists(Email);
  
      if (emailExists) {
        return res.redirect('/login');
      }
  
      const hashedPassword = await hashPassword(Password);
  
      if (!Fullname || !Email || !hashedPassword) {
        return res.send('Signup Failed: Invalid data provided.');
      }
  
      const user = {
        Fullname: Fullname,
        Email: Email,
        Password: hashedPassword,
      };
  
      await addUserToDatabase(user);
  
      req.session.user = user;
      res.redirect('/');
    } catch (error) {
      console.error('Error during signup:', error);
      res.send('An error occurred during signup.');
    }
  });
  

app.get('/login', (req, res) => {
  const user = req.session.user;
  if (user) {
    res.redirect('/');
  } else {
    res.render('pages/login');
  }
});

app.post('/loginsubmit', async (req, res) => {
  const Email = req.body.Email;
  const Password = req.body.Password;

  try {
    const userSnapshot = await db.collection('userData').where('Email', '==', Email).get();

    if (userSnapshot.empty) {
      return res.send('Login Failed: User not found.');
    }

    let userData;
    userSnapshot.forEach((doc) => {
      userData = doc.data();
    });

    const hashedPassword = userData.Password;

    const passwordMatch = await comparePasswords(Password, hashedPassword);

    if (passwordMatch) {
      req.session.user = userData;
      return res.redirect('/');
    } else {
      return res.send('Login Failed: Incorrect password.');
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.send('An error occurred during login.');
  }
});

app.get('/profile', (req, res) => {
  const user = req.session.user;

  if (!user) {
    return res.redirect('/login');
  }

  res.render('pages/profile', { user });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login');
  });
});



// Function to check if an email exists in the database
async function checkEmailExists(Email) {
  const snapshot = await db.collection('userData').where('Email', '==', Email).get();
  return !snapshot.empty;
}

// Function to hash a password using bcrypt
async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

// Function to add a user to the database
async function addUserToDatabase(user) {
  await db.collection('userData').add(user);
}

// Function to compare passwords
async function comparePasswords(enteredPassword, hashedPassword) {
  return bcrypt.compare(enteredPassword, hashedPassword);
}

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
