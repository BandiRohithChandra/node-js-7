const express = require('express')
const path = require('path')
const app = express()
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
let db = null
const dbPath = path.join(__dirname, 'twitterClone.db')
app.use(express.json())

const initializeAndDbServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server Running at localhost:3000/')
    })
  } catch (e) {
    console.log(`Db Error: ${e.message}`)
    process.exit(1)
  }
}

initializeAndDbServer()

app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body
  const hashedPassword = await bcrypt.hash(request.body.password, 10)
  const selectUserQuery = `
    SELECT * 
    FROM 
    user
    WHERE
    username = '${username}'`
  const dbUser = await db.get(selectUserQuery)

  if (dbUser === undefined) {
    const insertQuery = `
        INSERT INTO
        user(username, password, name, gender)
        VALUES(
            '${username}',
            '${hashedPassword}', 
            '${name}',
            '${gender}'
        )`
    if (password.length < 6) {
      response.status(400)
      response.send('Password is too short')
    } else {
      const createUser = await db.run(insertQuery)
      response.status(200)
      response.send('User created successfully')
    }
  } else {
    response.status(400)
    response.send('User already exists')
  }
})

app.post('/login/', async (request, response) => {
  const {username, password} = request.body

  const loginQuery = `
  SELECT *
  FROM user
  WHERE
  username = '${username}'`
  const dbUser = await db.get(loginQuery)
  if (dbUser === undefined) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched === true) {
      const payload = {username: username}
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
      response.send({jwtToken})
    } else {
      response.status(400)
      response.send('Invalid password')
    }
  }
})

const authenticateToken = (request, response, next) => {
  let jwtToken
  const authHeaders = request.headers['authorization']
  if (authHeaders !== undefined) {
    jwtToken = authHeaders.split(' ')[1]
  }
  if (jwtToken === undefined) {
    response.status(401)
    response.send('Invalid JWT Token')
  } else {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        response.status(401)
        response.send('Invalid JWT Token')
      } else {
        request.payload = payload
        next()
      }
    })
  }
}

app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const username = request.payload.username
  const getuserIdQuery = `
  SELECT user_id
  FROM user
  WHERE 
  username = ?`

  const {user_id} = await db.get(getuserIdQuery, [username])

  const getTweetsQuery = `
  SELECT 
  user.username , tweet.tweet, tweet.date_time AS dateTime
  FROM 
  follower 
  INNER JOIN user ON follower.following_user_id = user.user_id 
  INNER JOIN tweet ON user.user_id = tweet.user_id  
  WHERE
  follower.follower_user_id = ?
  ORDER BY tweet.date_time DESC
  LIMIT 4

  `
  const tweetDetails = await db.all(getTweetsQuery, [user_id])
  response.send(tweetDetails)
})

app.get('/user/following/', authenticateToken, async (request, response) => {
  const {username} = request.payload
  const getuserFollowingQuery = `
  SELECT user_id
  FROM 
  user
  WHERE username = ?
  `
  const {user_id} = await db.get(getuserFollowingQuery, [username])
  const tweetsQuery = `
SELECT u.name
      FROM follower
      INNER JOIN user AS u ON u.user_id = follower.following_user_id
      WHERE follower.follower_user_id = ?`

  const following = await db.all(tweetsQuery, [user_id])
  response.send(following)
})

app.get('/user/followers/', authenticateToken, async (request, response) => {
  const {username} = request.payload
  const followingQuery = `
  SELECT u.name
      FROM user AS u
      INNER JOIN follower AS f ON u.user_id = f.follower_user_id
      INNER JOIN user AS cu ON f.following_user_id = cu.user_id
      WHERE cu.username = ?
  `
  const usersList = await db.all(followingQuery, [username])
  response.send(usersList)
})

app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const {tweetId} = request.params
  // Extract the username from the JWT token payload
  const {username} = request.payload

  // Query the database to check if the user is following the author of the tweet
  const isFollowingQuery = `
      SELECT COUNT(*) AS following
      FROM follower AS f
      INNER JOIN user AS u ON f.follower_user_id = u.user_id
      INNER JOIN tweet AS t ON u.user_id = t.user_id
      WHERE f.following_user_id = t.user_id
      AND f.follower_user_id = (
        SELECT user_id FROM user WHERE username = ?
      )
      AND t.tweet_id = ?
    `
  const {following} = await db.get(isFollowingQuery, [username, tweetId])

  if (!following) {
    // If the user is not following the author of the tweet, return 401
    response.status(401).send('Invalid Request')
    return
  }

  // Query the database to fetch the tweet details, likes count, and replies count
  const tweetQuery = `
    SELECT tweet, date_time AS dateTime
    FROM tweet
    WHERE tweet_id = ?
  `
  const tweet = await db.get(tweetQuery, [tweetId])

  // Send the tweet details in the response
  response.send(tweet)
})

app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    // Extract the username from the JWT token payload
    const {username} = request.payload

    // Query the database to check if the user is following the author of the tweet
    const isFollowingQuery = `
      SELECT COUNT(*) AS following
      FROM follower AS f
      INNER JOIN user AS u ON f.follower_user_id = u.user_id
      INNER JOIN tweet AS t ON u.user_id = t.user_id
      WHERE f.following_user_id = t.user_id
      AND f.follower_user_id = (
        SELECT user_id FROM user WHERE username = ?
      )
      AND t.tweet_id = ?
    `
    const {following} = await db.get(isFollowingQuery, [username, tweetId])

    if (!following) {
      // If the user is not following the author of the tweet, return 401
      response.status(401).send('Invalid Request')
      return
    }

    // Query the database to get the list of usernames who liked the tweet
    const likesQuery = `
    SELECT u.username
    FROM user AS u
    INNER JOIN like AS l ON u.user_id = l.user_id
    WHERE l.tweet_id = ?
  `
    const likes = await db.all(likesQuery, [tweetId])
    response.send({likes: likes.map(like => like.username)})
  },
)

app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {username} = request.payload

    // Query the database to check if the user is following the author of the tweet
    const isFollowingQuery = `
      SELECT COUNT(*) AS following
      FROM follower AS f
      INNER JOIN user AS u ON f.follower_user_id = u.user_id
      INNER JOIN tweet AS t ON u.user_id = t.user_id
      WHERE f.following_user_id = t.user_id
      AND f.follower_user_id = (
        SELECT user_id FROM user WHERE username = ?
      )
      AND t.tweet_id = ?
    `
    const {following} = await db.get(isFollowingQuery, [username, tweetId])

    if (!following) {
      // If the user is not following the author of the tweet, return 401
      response.status(401).send('Invalid Request')
      return
    }

    // If the user is following the author of the tweet, return the list of replies
    const repliesQuery = `
    SELECT u.name, r.reply
    FROM user AS u
    INNER JOIN reply AS r ON u.user_id = r.user_id
    WHERE r.tweet_id = ?
  `
    const replies = await db.all(repliesQuery, [tweetId])
    response.send({replies})
  },
)

app.get('/user/tweets/', authenticateToken, async (request, response) => {
  const userId = request.payload.userId
  const userTweetQuery = `
  SELECT tweet.tweet,
  COUNT(like.like_id) AS likes,
  COUNT(reply.reply_id) AS replies,
  tweet.date_time AS dateTime
  FROM
  tweet
  LEFT JOIN like ON tweet.tweet_id = like.tweet_id
  LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
  WHERE tweet.user_id = ?
  GROUP BY tweet.tweet_id
  ORDER BY tweet.date_time DESC
  `
  const tweetsUser = await db.all(userTweetQuery, [userId])
  response.send(tweetsUser)
})

app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const {tweet} = request.body
  const {userId} = request.payload

  try {
    const insertQuery = `
      INSERT INTO tweet(tweet, user_id, date_time)
      VALUES (?, ?, datetime('now'));
    `

    // Execute the insert query with the tweet content and user ID
    await db.run(insertQuery, [tweet, userId])

    // Send success response
    response.status(201).send('Created a Tweet')
  } catch (error) {
    console.error('Error creating tweet:', error)
    // Send error response
    response.status(500).send('Internal Server Error')
  }
})

app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {userId} = request.payload

    try {
      // Query to fetch tweet details
      const getTweetQuery = `
      SELECT * 
      FROM tweet
      WHERE tweet_id = ?;
    `

      // Retrieve tweet details from the database
      const tweetDetails = await db.get(getTweetQuery, [tweetId])

      // Check if tweet exists
      if (!tweetDetails) {
        response.status(404).send('Tweet not found')
        return
      }

      // Check if the tweet belongs to the user
      if (tweetDetails.user_id !== userId) {
        response.status(401).send('Invalid Request')
        return
      }

      // Query to delete the tweet from the database
      const deleteTweetQuery = `
      DELETE FROM tweet
      WHERE tweet_id = ?;
    `

      // Execute the delete query
      await db.run(deleteTweetQuery, [tweetId])

      // Send success response
      response.send('Tweet Removed')
    } catch (error) {
      console.error('Error deleting tweet:', error)
      // Send error response
      response.status(500).send('Internal Server Error')
    }
  },
)

module.exports = app
