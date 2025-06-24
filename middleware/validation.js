const Joi = require("joi");

const validateRegistration = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])")).required()
      .messages({
        "string.pattern.base": "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character"
      }),
    firstName: Joi.string().min(2).max(50).required(),
    lastName: Joi.string().min(2).max(50).required(),
    confirmPassword: Joi.string().valid(Joi.ref("password")).required()
      .messages({
        "any.only": "Passwords do not match"
      }),
    role : Joi.string().valid("user", "admin").default("admin")
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: "Validation error",
      errors: error.details.map(detail => detail.message)
    });
  }

  next();
};

const validateLogin = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: "Validation error",
      errors: error.details.map(detail => detail.message)
    });
  }

  next();
};

const validatePasswordReset = (req, res, next) => {
  const schema = Joi.object({
    token: Joi.string().required(),
    newPassword: Joi.string().min(8).pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])")).required()
      .messages({
        "string.pattern.base": "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character"
      }),
    confirmPassword: Joi.string().valid(Joi.ref("newPassword")).required()
      .messages({
        "any.only": "Passwords do not match"
      })
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: "Validation error",
      errors: error.details.map(detail => detail.message)
    });
  }

  next();
};

module.exports = {
  validateRegistration,
  validateLogin,
  validatePasswordReset
};
