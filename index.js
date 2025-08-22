import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';
import { UserRepository } from './user-repository.js';

dotenv.config();

const app = express();
app.disable('x-powered-by');

app.set('view engine', 'ejs');

app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

app.use((req, _res, next) => {
	req.session = { user: null };
	const token = req.cookies.access_token;
	if (token) {
		try {
			const data = jwt.verify(token, process.env.JWT_SECRET);
			req.session.user = data;
		} catch (error) {
			console.error(error);
		}
	}
	next();
});

app.get('/', (req, res) => {
	const { user } = req.session;
	res.render('index', user);
});

app.get('/protected', (req, res) => {
	const { user } = req.session;
	if (!user) return res.status(401).json({ error: 'Unauthorized' });
	res.render('protected', user);
});

app.post('/logout', (_req, res) => {
	res.clearCookie('access_token');
	res.end();
});

app.post('/register', async (req, res) => {
	const { username, password } = req.body;

	try {
		const id = await UserRepository.create({ username, password });
		res.status(201).json({ id });
	} catch (error) {
		console.error(error);
		res.status(400).json({ error: error.message });
	}
});

app.post('/login', async (req, res) => {
	const { username, password } = req.body;

	try {
		const user = await UserRepository.login({ username, password });
		const token = jwt.sign(
			{ id: user._id, username: user.username },
			process.env.JWT_SECRET,
			{ expiresIn: '1h' },
		);
		res.cookie('access_token', token, {
			httpOnly: true, //la cookie solo se puede acceder desde el servidor
			secure: process.env.NODE_ENV === 'production', //la cookie solo se puede enviar a través de HTTPS
			sameSite: 'strict', //la cookie solo se puede acceder desde el mismo dominio
			maxAge: 1000 * 60 * 60, //tiempo de validez 1 hora
		});
		res.status(200).json({ user });
	} catch (error) {
		console.error(error);
		res.status(400).json({ error: error.message });
	}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
