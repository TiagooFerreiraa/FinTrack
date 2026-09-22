const express = require('express');
const path = require('path');
const session = require('express-session');

require('dotenv').config();

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'fintrack-dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8,
        secure: false
    }
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

const routes = require('./routes');
app.use('/', routes);

app.use((req, res) => {
    res.status(404).render('404', {
        title: 'Página não encontrada',
        user: req.session.user || null
    });
});

app.use((err, req, res, next) => {
    console.error('Erro interno:', err);
    res.status(500).render('error', {
        title: 'Erro interno',
        message: 'Ocorreu um erro inesperado. Tenta de novo mais tarde.',
        user: req.session.user || null
    });
});

if (require.main === module) {
    const port = Number(process.env.PORT || 3000);
    app.listen(port, () => {
        console.log(`Server running at port ${port}`);
    });
}

module.exports = app;