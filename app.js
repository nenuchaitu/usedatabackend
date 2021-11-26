//start DB and server
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const express = require("express");
//user authentication
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
//startDb and Server
const app = express();
app.use(express.json());
app.use(cors());
const dbPath = path.join(__dirname, "userData.db");
let db = null;
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(process.env.PORT || 3000, () => {
      console.log(`Server is Running at http://localhost:3000`);
    });
  } catch (e) {
    console.log(`Db error '${e.message}'`);
    process.exit(1);
  }
};
initializeDbAndServer();
// authentication
const validatePassword = (password) => {
  return password.length > 6;
};
//validate data
const validateData = (id, title, body, userId) => {
  if (id === "" || title === "" || body === "" || userId === "") {
    return false;
  } else {
    return true;
  }
};

const authenticationToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send({ error_msg: "Invalid JWT Token" });
  } else {
    jwt.verify(jwtToken, "passwordishidden", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send({ error_msg: "Invalid JWT Token" });
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

//register user
app.post("/register", async (request, response) => {
  const { userId, password } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `SELECT * FROM user WHERE id = '${userId}';`;
  const databaseUser = await db.get(selectUserQuery);
  if (databaseUser === undefined) {
    const createUserQuery = `
     INSERT INTO
      user (id,password)
     VALUES
      (
       '${userId}',
       '${hashedPassword}'
      );`;
    if (validatePassword(password)) {
      await db.run(createUserQuery);
      response.send({ message: "User created successfully" });
    } else {
      response.status(400);
      response.send({ error_msg: "Password is too short" });
    }
  } else {
    response.status(400);
    response.send({ error_msg: "User already exists" });
  }
});
//get user
app.get("/user", async (request, response) => {
  const getQuery = `SELECT * FROM user;`;
  const userList = await db.all(getQuery);
  response.send({ users: userList });
});
//login
app.post("/login/", async (request, response) => {
  const { userId, password } = request.body;
  const getUserQuery = `SELECT * FROM user WHERE id='${userId}';`;
  const user = await db.get(getUserQuery);
  if (user === undefined) {
    response.status(400);
    response.send({ error_msg: "Invalid user" });
  } else {
    const isPasswordRight = await bcrypt.compare(password, user.password);
    if (isPasswordRight) {
      const payLoad = user.id;
      const jwtToken = jwt.sign(payLoad, "passwordishidden");
      response.send({ jwt_token: jwtToken });
    } else {
      response.status(400);
      response.send({ error_msg: "Invalid password" });
    }
  }
});
//get user details by userId
app.get("/user/:userId/", authenticationToken, async (request, response) => {
  const { userId } = request.params;
  const getUsersQuery = `SELECT * 
    FROM 
    data
    WHERE 
    user_id='${userId}';`;
  const userData = await db.all(getUsersQuery);
  response.send({ userFiles: userData });
});
//
app.post("/data", async (request, response) => {
  const { id, title, body, userId } = request.body;
  const selectUserQuery = `SELECT * FROM user WHERE id = '${userId}';`;
  const databaseUser = await db.get(selectUserQuery);
  try {
    if (databaseUser !== undefined) {
      const insertDataQuery = `
     INSERT INTO
      data (id,title,body,user_id)
     VALUES
      ('${id}',
      '${title}',
      '${body}',
       '${userId}'
      );`;
      if (validateData(id, title, body, userId)) {
        await db.run(insertDataQuery);
        response.send({ message: "Data entered successfully" });
      } else {
        response.status(400);
        response.send({ error_msg: "Invalid data" });
      }
    }
  } catch (e) {
    response.status(400);
    response.send({ error_msg: e });
  }
});
//export module
module.exports = app;
