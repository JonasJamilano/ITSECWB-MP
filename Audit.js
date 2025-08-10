const mongoose = require('mongoose');

const auditSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'AdminUser' },  // Corrected ref
  username: String,
  action: String,
  details: String,
}, { timestamps: true }); // adds createdAt and updatedAt automatically

module.exports = mongoose.model('Audit', auditSchema);
