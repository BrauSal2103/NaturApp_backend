import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';


const userSchema = new mongoose.Schema({
  name:     { type: String, required: true },
  email:    { type: String, required: true, unique: true,
              lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  phone:    { type: String, default: '' },
  address:  {
    street:  { type: String },
    city:    { type: String },
    zipCode: { type: String }
  },
  role:     { type: String, enum: ['customer', 'admin'],
              default: 'customer' }
}, { timestamps: true });


// Hash de contraseña antes de guardar
// Hash de contraseña antes de guardar (Versión Mongoose Moderno)
userSchema.pre('save', async function() {
  // Si la contraseña no ha sido modificada, terminamos la ejecución aquí
  if (!this.isModified('password')) {
    return;
  }
  
  // Generamos la "sal" y encriptamos directamente
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function(candidate) {
  return bcrypt.compare(candidate, this.password);
};


export default mongoose.model('User', userSchema);

