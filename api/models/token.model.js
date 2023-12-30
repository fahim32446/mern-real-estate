import mongoose from 'mongoose';

const token = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  resetToken: {
    type: String,
    required: true,
  },
  resetTokenExpiry: {
    type: Date,
    required: true,
  },
});

const tokens = mongoose.model('tokens', token);

export default tokens;
