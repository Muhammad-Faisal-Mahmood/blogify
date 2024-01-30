const { Schema, model } = require("mongoose");
const { createHmac, randomBytes } = require("crypto");

const userSchema = new Schema(
  {
    fullName: {
      type: "string",
      required: true,
    },
    email: {
      type: "string",
      required: true,
      unique: true,
    },
    salt: {
      type: "string",
    },
    password: {
      type: "string",
      required: true,
    },
    profileImageURL: {
      type: "string",
      default: "/images/defaultAvatar.jpg",
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN"],
      default: "USER",
    },
  },
  { timestamps: true }
);

userSchema.pre("save", function (next) {
    const user = this;
    if (!user.isModified("password")) return next(); // Skip if password is not modified
  
    const salt = randomBytes(16).toString('hex'); // Generate a random salt
    const hashedPassword = createHmac("sha256", salt)
      .update(user.password)
      .digest("hex");
  
    user.salt = salt; // Set the salt for the user
    user.password = hashedPassword; // Set the hashed password
    next();
  });
  
const User = model("user", userSchema);
module.exports = User;
