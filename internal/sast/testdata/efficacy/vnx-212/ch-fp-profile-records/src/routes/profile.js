const Profile = require('../models/profile');
const UserSettings = require('../models/userSettings');

async function getProfile(req, res) {
  const profile = await Profile.findOne({ userId: req.user.id });
  res.json(profile);
}

async function getSettings(req, res) {
  const settings = await UserSettings.findOne({ userId: req.user.id });
  res.json(settings);
}

async function getUser(req, res) {
  const user = await User.findById(req.params.id).select('-password -__v');
  res.json(user);
}

module.exports = { getProfile, getSettings, getUser };
