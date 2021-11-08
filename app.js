const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const User = require('./userModel')

const app = express()

const { PORT = 5000, SALT_ROUNDS = 10, MONGO_USER, MONGO_PASSWORD, MONGO_DB } = process.env

const mongoUri = `mongodb+srv://${MONGO_USER}:${MONGO_PASSWORD}@cluster0.txzjm.mongodb.net/${MONGO_DB}?retryWrites=true&w=majority`

app.use(express.json())

app.get('/health', (req, res) => {
	res.json({ message: 'Alive and well. Thanks for asking :)' })
})

app.post('/register', async (req, res) => {
	// 1. Get username and password
	const { username, password } = req.body
	try {
		// 2. Check if user exists
		const userData = await User.find({ username })
		if (userData.length) {
			// User exists, because userData is not an empty array
			return res.json({ error: `User ${username} already registered. Please try a different username.` })
		}
		// 3. Generate salt rounds
		const saltRounds = await bcrypt.genSalt(SALT_ROUNDS)

		// 4. Hash password
		const hashedPassword = await bcrypt.hash(password, saltRounds)

		// 5. Create user model
		const user = new User({ username, password: hashedPassword })

		// 6. Save user
		await user.save()

		// 7. Send 'success' message
		res.json({ message: `User ${username} successfully registered.` })
	} catch (e) {
		console.log('REGISTER ERROR: ', e)
		res.status(500).json({ error: `Could not register user ${username}. Please try again later.` })
	}
})

app.post('/login', async (req, res) => {
	const { username, password } = req.body

	try {
		const [userData] = await User.find({ username })
		if (!userData) {
			return res.status(404).json({ error: `User ${username} does not exist.` })
		}

		const { password: hashedPassword } = userData

		const isCorrectPassword = await bcrypt.compare(password, hashedPassword)
		if (!isCorrectPassword) {
			return res.status(401).json({ error: `Incorrect password. Please try again.` })
		}

		res.json({ message: `User ${username} successfully logged in.` })
	} catch (e) {
		console.log('LOGIN ERROR: ', e)
		res.status(500).json({ error: `Could not register user ${username}. Please try again later.` })
	}
})

mongoose
	.connect(mongoUri)
	.then(() => app.listen(PORT, () => console.log(`App running on port ${PORT}...`)))
	.catch(error => {
		throw error
	})
