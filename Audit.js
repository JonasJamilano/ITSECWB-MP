const mongoose = require('mongoose');

const auditSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },  // fixed ref here
  username: String,
  action: String,
  details: String,
}, { timestamps: true });

module.exports = mongoose.model('Audit', auditSchema);
