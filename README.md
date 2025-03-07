# Using JSON Web Tokens

## Introduction

Use `Node.js`, `Express` and `Knex` to build an API with authentication and authorization using JSON Web Tokens.

## Instructions

### Task 1: Project Setup and Submission

Your assignment page on Canvas should contain instructions for submitting this project. If you are still unsure, reach out to School Staff.

### Task 2: Minimum Viable Product

You will complete the following tasks and do any extra wiring and package installation necessary for the app to compile and pass all tests.

#### 2A - Database Access Functions

Write the following user access functions inside `api/users/users-model.js`:

- [x] `find`
- [x] `findBy`
- [x] `findById`

#### 2B - Middleware Functions

Write the following auth middlewares inside `api/auth/auth-middleware.js`:

- [x] `restricted`
- [x] `only`
- [x] `checkUsernameExists`
- [ ] `validateRoleName`

#### 2C - Endpoints

Authentication will be implemented using JSON Web Tokens.

Write the following endpoints inside `api/auth/auth-router.js`:

- [ ] `[POST] /api/auth/register`
- [x] `[POST] /api/auth/login`

The endpoints inside `api/users/users-router.js` are built already but check them out:

- [x] `[GET] /api/users` - only users with a valid token can access
- [x] `[GET] /api/users/:user_id` - only users with a valid token AND a role of 'admin' can access

#### 2D - Secrets File

Complete the `secrets/index.js` file.

#### Users Schema

| field    | data type        | metadata                                      |
| :------- | :--------------- | :-------------------------------------------- |
| user_id  | unsigned integer | primary key, auto-increments, generated by db |
| username | string           | required, unique                              |
| password | string           | required                                      |
| role_id  | unsigned integer | foreign key, required                         |

#### Roles Schema

| field     | data type        | metadata                                      |
| :-------- | :--------------- | :-------------------------------------------- |
| role_id   | unsigned integer | primary key, auto-increments, generated by db |
| role_name | string           | required, unique                              |

#### Notes

- Run tests locally executing `npm test`.
- The project comes with `migrate`, `rollback` and `seed` scripts in case you need to reset the database.
- You are welcome to create additional files but **do not move or rename existing files** or folders.
- Do not alter your `package.json` file except to install extra libraries or add extra scripts. Do not update existing libraries.
- In your solution, it is essential that you follow best practices and produce clean and professional results.
- Schedule time to review, refine, and assess your work.
- Perform basic professional polishing including spell-checking and grammar-checking on your work.

### Task 3: Stretch Goals

- Build a React application that implements components to register, login and view a list of users. Gotta keep sharpening your React skills.
