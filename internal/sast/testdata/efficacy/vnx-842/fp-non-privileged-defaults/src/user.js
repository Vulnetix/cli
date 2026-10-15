const userSchema = new mongoose.Schema({
  role: {
    type: String,
    enum: ['admin', 'viewer'],
    default: 'viewer',
  },
  theme: { type: String, default: 'admin' },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
});
