const express = require("express");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});
const UserSchema = new mongoose.Schema({
	discordId: String,
	username: String,
	avatar: String,
	email: String,
	createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", UserSchema);

// Middleware
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(bodyParser.json());
app.use(passport.initialize());

// Passport Discord Strategy
passport.use(
	new DiscordStrategy(
		{
			clientID: process.env.DISCORD_CLIENT_ID,
			clientSecret: process.env.DISCORD_CLIENT_SECRET,
			callbackURL: `${process.env.SERVER_URL}/auth/discord/callback`,
			scope: ["identify", "email"],
		},
		async (accessToken, refreshToken, profile, done) => {
			try {
				let user = await User.findOne({ discordId: profile.id });
				if (!user) {
					user = await User.create({
						discordId: profile.id,
						username: profile.username,
						avatar: profile.avatar,
						email: profile.email,
					});
				}
				return done(null, user);
			} catch (err) {
				return done(err, null);
			}
		}
	)
);

// Routes
app.get("/auth/discord", passport.authenticate("discord"));

app.get(
	"/auth/discord/callback",
	passport.authenticate("discord", { session: false }),
	(req, res) => {
		const token = jwt.sign({ id: req.user.discordId }, process.env.JWT_SECRET, {
			expiresIn: "1h",
		});
		res.redirect(`${process.env.CLIENT_URL}/loginRedirect?token=${token}`);
	}
);

app.get("/auth/me", async (req, res) => {
	const token = req.headers.authorization?.split(" ")[1];
	if (!token) return res.status(401).json({ message: "Unauthorized" });
	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);
		const user = await User.findOne({ discordId: decoded.id });
		if (!user) return res.status(404).json({ message: "User not found" });
		res.json(user);
	} catch (err) {
		res.status(401).json({ message: "Invalid token" });
	}
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
