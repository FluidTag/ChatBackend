const express = require("express")
const http = require("http");
const WebSocket = require("ws");
const mysql2 = require("mysql2/promise")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken");
const { transcode } = require("buffer");
const { create } = require("domain");
const app = express()
const port = 3000
const tokenSecret = "TemporarySecret"
const activeWebsockets = new Map(); // id -> websocket
const onlineUsers = new Map(); // id -> Prescence state (online, last)
const friendMap = new Map(); // id -> Set<friend ids>

app.use(express.json())

const pool = mysql2.createPool({
    host: "localhost",
    user: "root",
    password: "0b71df800317ab69",
    database: "main",
    waitForConnections: true,
    connectionLimit: 10,
    maxIdle: 10,
    idleTimeout: 60000,
    queueLimit: 0,
})

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({message: "Missing or malformed Authorization Header"});
    }

    const token = authHeader.substring("Bearer ".length);
    try {
        const payload = jwt.verify(token, tokenSecret);
        req.user = payload;
        next();
    } catch {
        return res.status(403).json({message: "Unauthorized token"})
    }
}

app.get("/", async (req, res) => {
    res.send("Hello!")
})

app.post("/signup", async (req, res) => {
    console.log(req.body);
    console.log("Body Recieved");

    const saltRounds = 12;
    const {username, password} = req.body;
    let connection;

    try {
        connection = await pool.getConnection();

        // Check if username already exists
        const [existing] = await connection.query("SELECT * FROM users WHERE username = ?;", [username])
        if (existing.length > 0) {
            return res.status(401).json({"message": "Username already exists"});
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds)
        await connection.beginTransaction();

        const [result] = await connection.query(
            "INSERT INTO users (username, hashedPassword) VALUES (?, ?);"
            , [username, hashedPassword]
        )

        console.log(result);
        await connection.commit();

        const payload = {
            id: result.insertId,
            username: username
        }

        const token = jwt.sign(payload, tokenSecret, {"expiresIn": "1h"})
        return res.status(201).json({"token": token})
    } catch (err) {
        console.error(err);
        await connection.rollback();
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

app.post("/login", async (req, res) => {
    const {username, password} = req.body;
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.query("SELECT * FROM users WHERE username = ?", [username]);
        
        if (rows.length == 0) {
            return res.status(401).json({"message": "Incorrect username or password"});
        }

        const user = rows[0];
        const savedHash = user.hashedPassword;
        const authorized = await bcrypt.compare(password, savedHash);

        if (!authorized) {
            return res.status(401).json({"message": "Incorrect username or password"});
        }

        const payload = {
            id: user.id,
            username: username
        }
        
        const [friends] = await connection.query(
            `SELECT friend_id FROM friendships
            WHERE user_id = ? AND status = 'accepted'
            UNION ALL
            SELECT user_id AS friend_id FROM friendships
            WHERE friend_id = ? AND status = 'accepted'
            `, [user.id, user.id]
        )

        friendMap.put(user.id, friends.map((data) => data.friend_id))

        const token = jwt.sign(payload, tokenSecret, {"expiresIn": "1h"})
        return res.status(200).json({"token": token});
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
});

app.post("/profile", verifyToken, async (req, res) => {
    const {searchParam} = req.body; //username
    const user = req.user;
    let connection

    try {
        connection = await pool.getConnection();

        const [result] = await connection.query("SELECT id, username FROM users WHERE (username = ?)", [searchParam])
        if (result.length == 0) {
            return res.status(404).json({"message": "User not found"});
        }

        const dataTarget = result[0];
        const [id1, id2] = [Number(user.id), Number(dataTarget.id)].sort((a, b) => a - b);

        const [friendship] = await connection.query(
            `
            SELECT f.status, f.sender_id
            FROM friendships f
            WHERE f.user_id = ? AND f.friend_id = ?
            `,
            [id1, id2]
        );

        if (friendship.length > 0) {
            dataTarget.relationship = friendship[0];
        }

        return res.status(200).json(dataTarget)
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"})
    } finally {
        if (connection) connection.release();
    }
})

app.get("/getFriends", verifyToken, async (req, res) => {
    const user = req.user;
    let connection;

    try {
        connection = await pool.getConnection();

        const [rows] = await connection.query(
            `
                SELECT f.friend_id AS friendId, u.username, f.status, f.sender_id
                FROM friendships f
                JOIN users u ON f.friend_id = u.id
                WHERE f.user_id = ?

                UNION ALL

                SELECT f.user_id as friendId, u.username, f.status, f.sender_id
                FROM friendships f
                JOIN users u ON f.user_id = u.id
                WHERE f.friend_id = ?;
            `,
            [user.id, user.id]
        )

        const formattedJson = rows.map((data) => {
            return {
                id: data.friendId,
                username: data.username,
                relationship: {
                    status: data.status,
                    sender_id: data.sender_id,
                }
            }
        })
        
        return res.status(200).json({
            friends: formattedJson
        })
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"})
    } finally {
        if (connection) connection.release();
    }
})

app.post("/acceptFriend", verifyToken, async (req, res) => {
    const {targetUsername} = req.body;
    const user = req.user;
    let connection;

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        let [friend] = await connection.query(
            `SELECT * FROM users WHERE (username = ?)`
            ,[targetUsername]
        )

        if (friend.length == 0) {
            await connection.rollback();
            return res.status(404).json({"message": "Friend user could not be found"})
        }

        friend = friend[0];
        const [id1, id2] = [Number(user.id), Number(friend.id)].sort((a, b) => a - b);

        const [existingFriendship] = await connection.query(
            `SELECT * FROM friendships WHERE (user_id = ? AND friend_id = ?);`
            ,[id1, id2]
        )

        if (existingFriendship.length == 0) {
            await connection.rollback();
            return res.status(404).json({"message": "A friendship doesn't exist between those two users"})
        }

        const [result] = await connection.query(
            `
            UPDATE friendships
            SET status = 'accepted'
            WHERE (user_id = ? AND friend_id = ?)
            AND sender_id != ?
            AND status = 'pending'
            ;
            `
            ,[id1, id2, user.id] 
        )

        const [relationshipRes] = await connection.query(
            `SELECT sender_id, status FROM friendships
            WHERE (user_id = ? AND friend_id = ?)
            `
            ,[id1, id2]
        )
        
        if (result.affectedRows == 0) {
            await connection.rollback();
            return res.status(400).json({"message": "Unable to accept a friend request you sent"})
        }

        await connection.commit();
        const targetWebsocket = activeWebsockets.get(friend.id)
        friendMap.get(friend.id)?.add(user.id);
        friendMap.get(user.id)?.add(friend.id);

        if (targetWebsocket) {
            targetWebsocket.send(JSON.stringify({
                type: "FRIEND_ACCEPTED",
                payload: {
                    id: user.id,
                    username: user.username,
                    relationship: relationshipRes[0]
                }
            }))
        }

        return res.status(200).json({"message": "Successfuly updated friend status"})
    } catch (err) {
        if (connection) await connection.rollback();
        
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"})
    } finally {
        if (connection) connection.release();
    }
})

app.post("/removeFriend", verifyToken, async (req, res) => {
    const {targetUsername} = req.body;
    const user = req.user;
    let connection;

    if (user.username == targetUsername) {
        return res.status(400).json({"message": "You cannot unfriend yourself"})
    }

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [targetData] = await connection.query("SELECT * FROM users WHERE username = ?", [targetUsername])
        if (targetData.length == 0) {
            await connection.rollback();
            return res.status(404).json({"message": "Could not find that user"})
        }

        const [id1, id2] = [Number(user.id), Number(targetData[0].id)].sort((a, b) => a - b);
        const [result] = await connection.query(
            "DELETE FROM FRIENDSHIPS WHERE (user_id = ? AND friend_id = ?);", [id1, id2]
        )

        if (result.affectedRows == 0) {
            return res.status(400).json({"message": "Friendship not found"})
        }

        await connection.commit();
        const targetWebsocket = activeWebsockets.get(targetData[0].id)
        friendMap.get(targetData[0].id)?.delete(user.id);
        friendMap.get(user.id)?.delete(targetData[0].id);

        if (targetWebsocket) {
            targetWebsocket.send(JSON.stringify({
                type: "FRIEND_REMOVED",
                payload: {
                    id: user.id,
                    username: user.username,
                }
            }))
        }

        return res.status(200).json({"message": "Successfuly removed friend"});
    } catch (err) {
        if (connection) await connection.rollback();

        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

app.post("/friendRequest", verifyToken, async (req, res) => {
    const {targetUsername} = req.body;
    const user = req.user;

    let connection
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [target] = await connection.query("SELECT * FROM users WHERE username = ?", [targetUsername])
        if (target.length == 0) {
            await connection.rollback();
            return res.status(404).json({"message": "User not found"});
        }

        const friendData = target[0];
        const [id1, id2] = [Number(user.id), Number(friendData.id)].sort((a, b) => a - b);

        if (id1 == id2) {
            await connection.rollback();
            return res.status(400).json({"message": "You cannot friend yourself"});
        }

        const [existing] = await connection.query(
            "SELECT * FROM friendships WHERE (user_id = ? AND friend_id = ?);",
            [id1, id2]
        );

        if (existing.length > 0) {
            await connection.rollback();
            return res.status(400).json({"message": "This friend request already exists"})
        }

        await connection.query("INSERT INTO friendships (user_id, friend_id, status, sender_id) VALUES (?, ?, ?, ?)",
            [id1, id2, "pending", user.id]
        );
         
        await connection.commit();
        const targetWebsocket = activeWebsockets.get(friendData.id)
        if (targetWebsocket) {
            console.log("Found websocket")
            targetWebsocket.send(JSON.stringify({
                type: "FRIEND_REQUEST",
                payload: {
                    id: user.id,
                    username: user.username,
                    relationship: {
                        status: "pending",
                        sender_id: user.id,
                    }
                }
            }))
        } 

        return res.status(201).json({"message": "Friend Request Sent Successfuly"})
    } catch (err) {
        if (connection) await connection.rollback();

        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"})
    } finally {
        if (connection) connection.release();
    }
})


///////////////////////////// Conversation Handling
app.get("/getConversations", verifyToken, async (req, res) => {
    const user = req.user;
    let connection;

    try {
        connection = await pool.getConnection();

        const [rows] = await connection.query(
            `
            SELECT c.conversationId, c.isGroup, c.lastMessage, UNIX_TIMESTAMP(c.lastUpdated) AS lastUpdated,
            CASE
                WHEN c.isGroup = TRUE THEN c.conversationName
                ELSE u.username
            END AS displayName,
            COALESCE(
                (SELECT 
                    JSON_ARRAYAGG(
                        JSON_OBJECT(
                            'conversationId', c.conversationId,
                            'messageId', messageId,
                            'fromId', fromId,
                            'username', username,
                            'created', UNIX_TIMESTAMP(created),
                            'content', content,
                            'edited', edited
                        )
                    )
                    FROM (
                        SELECT messages.*, users.username FROM messages 
                        JOIN users ON users.id = messages.fromId
                        WHERE messages.conversationId = c.conversationId
                        ORDER BY messages.created ASC, messages.messageId ASC LIMIT 20
                    ) AS sub
                ),
                JSON_ARRAY()
            ) AS messages
            FROM conversation_members m
            JOIN conversations c ON c.conversationId = m.conversationId

            LEFT JOIN conversation_members other ON 
                other.conversationId = c.conversationId
                AND other.user_id != m.user_id
                AND c.isGroup = FALSE
            LEFT JOIN users u ON
                u.id = other.user_id

            WHERE m.user_id = ?
            GROUP BY c.conversationId, u.username;
            `, [user.id]
        )

        return res.status(200).json({
            "conversations": rows
        })
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

app.post("/createGroupchat", verifyToken, async (req, res) => {
    const user = req.user;
    const {targetUIDS, conversationName} = req.body;
    let connection;

    if (targetUIDS.length == 0) {
        return res.status(400).json({"message": "You must add at least one person to a groupchat"})
    }

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [created] = await connection.query(`INSERT INTO conversations (conversationName, isGroup) VALUES (?, ?)`, [conversationName, true])
        targetUIDS.push(user.id);

        const values = targetUIDS.map((id) => [created.insertId, id])
        await connection.query(`INSERT INTO conversation_members (conversationId, user_id) VALUES ?`, [values])
        
        await connection.commit();

        targetUIDS.forEach((id) => {
            const targetWebsocket = activeWebsockets.get(id);
            if (!targetWebsocket) return;

            const convo = {
                conversationId: created.insertId,
                isGroup: 1,
                lastMessage: null,
                lastUpdated: Math.floor(Date.now() / 1000),
                created: Math.floor(Date.now() / 1000),
                displayName: conversationName,
                messages: []
            }

            targetWebsocket.send(JSON.stringify({
                type: "CONVERSATION_CREATED",
                payload: convo
            }))
        })

        return res.status(201).json({"message": "Successfuly created Groupchat"});
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

app.post("/leaveConversation", verifyToken, async (req, res) => {
    const user = req.user;
    const {conversationId} = req.body;
    let connection;

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [result] = await connection.query(`
            SELECT 1 FROM conversation_members WHERE conversationId = ? AND user_id = ?`
            , [conversationId, user.id]
        )

        if (result.length == 0) {
            await connection.rollback();
            return res.status(404).json({"message":"You are not a member of this conversation or it doesnt exist"})
        }

        await connection.query(`
            DELETE FROM conversation_members WHERE conversationId = ? AND user_id = ?`
            , [conversationId, user.id]
        );

        let [remainingMembers] = await connection.query(
            `SELECT cm.user_id, c.isGroup 
            FROM conversation_members cm 
            JOIN conversations c ON c.conversationId = cm.conversationId
            WHERE cm.conversationId = ?`
            , [conversationId]
        )

        if (remainingMembers.length == 0 || (remainingMembers.length == 1 && (remainingMembers[0].isGroup == 0))) {
            await connection.query(`DELETE FROM conversations WHERE conversationId = ?`, [conversationId])
        }

        await connection.commit();
        remainingMembers.push({"user_id": user.id}) // To Notify All Websockets of leave
        remainingMembers.forEach((data) => {
            const targetWebsocket = activeWebsockets.get(data.user_id);
            if (!targetWebsocket) return;

            targetWebsocket.send(JSON.stringify({
                type: "CONVERSATION_LEFT",
                payload: {
                    id: user.id,
                    conversationId: conversationId
                }
            }))
        })

        return res.status(200).json({"message": "Successfuly left conversation"});
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
});

app.post("/openDM", verifyToken, async (req, res) => {
    const user = req.user;
    const {targetUID} = req.body;
    let connection;

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [id1, id2] = [Number(user.id), Number(targetUID)].sort((a, b) => a - b);
        const [friendship] = await connection.query(
            `
                SELECT * FROM friendships WHERE (user_id = ? AND friend_id = ?);
            `, [id1, id2]
        )

        if ((friendship.length > 0 && friendship[0].status != 'accepted') || friendship.length == 0) {
            await connection.rollback();

            return res.status(403).json({"message": "Must be friends to open conversation"});
        }

        const [existingConversation] = await connection.query(
            `
            SELECT cm.conversationId, c.isGroup
            FROM conversation_members cm
            JOIN conversations c ON c.conversationId = cm.conversationId
            WHERE user_id IN (?, ?) AND c.isGroup = false
            GROUP BY conversationId
            HAVING COUNT(DISTINCT user_id) = 2;
            `,
            [user.id, targetUID]
        )

        if (existingConversation.length > 0) {
            await connection.rollback();
            return res.status(200).json({
                "conversationId": existingConversation[0].conversationId,
                "message": "Conversation exists already"
            })
        }

        const [creationResultConvo] = await connection.query(
            `INSERT INTO conversations () VALUES ();`
        )

        await connection.query(
            `
            INSERT INTO conversation_members (conversationId, user_id)
            VALUES
            (?, ?),
            (?, ?);
            `,
            [creationResultConvo.insertId, user.id,
            creationResultConvo.insertId, targetUID]
        )

        const [[targetDetails]] = await connection.query(`SELECT * FROM users WHERE id = ?`, [targetUID])

        await connection.commit();
        const targetIds = [user.id, targetUID]
        targetIds.forEach((id) => {
            const targetWebsocket = activeWebsockets.get(id);
            if (!targetWebsocket) return;

            targetWebsocket.send(JSON.stringify({
                type: "CONVERSATION_CREATED",
                payload: {
                    conversationId: creationResultConvo.insertId,
                    isGroup: 0,
                    lastMessage: null,
                    lastUpdated: Math.floor(Date.now() / 1000),
                    displayName: id != user.id ? user.username : targetDetails.username,
                    messages: []
                }
            }))
        })

        return res.status(201).json({
            "message": "Conversation Created Successfuly",
            "conversationId": creationResultConvo.insertId,
        })
    } catch (err) {
        if (connection) await connection.rollback();

        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"})
    } finally {
        if (connection) connection.release();
    }
})

app.post("/sendMessage", verifyToken, async (req, res) => {
    let user = req.user;
    const {content, conversationId} = req.body;

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        // Check existence and authorization
        const [existingConvo] = await connection.query(
            `
            SELECT *
            FROM conversations c
            JOIN conversation_members m ON m.conversationId = ? AND m.user_id = ? 
            `, [conversationId, user.id]
        )

        if (existingConvo.length == 0) {
            await connection.rollback();
            return res.status(404).json({"message": "You are not a member of this conversation or it doesn't exist."});
        }

        const [createdMessage] = await connection.query(
            `INSERT INTO messages (conversationId, fromId, content) VALUES (?, ?, ?)`,
            [conversationId, user.id, content]
        )

        await connection.query(
            `UPDATE conversations SET lastMessage = ?, lastUpdated = CURRENT_TIMESTAMP WHERE conversationId = ?`,
            [content, conversationId]
        )

        const [conversationMembers] = await connection.query(`
            SELECT user_id FROM conversation_members WHERE conversation_members.conversationId = ?
        `, [conversationId])
        
        await connection.commit();
        const msgPayload = {
            messageId: createdMessage.insertId,
            conversationId: conversationId,
            fromId: user.id,
            username: user.username,
            content: content,
            created: Math.floor(Date.now() / 1000),
            edited: 0,
        }

        conversationMembers.forEach((member) => {

            const targetWebsocket = activeWebsockets.get(member.user_id);
            if (!targetWebsocket || !targetWebsocket.readyState == WebSocket.OPEN) return

            targetWebsocket.send(JSON.stringify({
                type: "MESSAGE_SENT",
                payload: msgPayload
            }))
        })

        return res.status(201).json({"message": "Successfuly sent message", "data": msgPayload});
    } catch (err) {
        if (connection) await connection.rollback();

        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

app.post("/deleteMessage", verifyToken, async (req, res) => {
    const user = req.user;
    const {messageId} = req.body;
    let connection;

    try {
        connection = await pool.getConnection();

        const [authCheck] = await connection.query(
            `SELECT m.messageId, m.conversationId
            FROM messages m
            JOIN conversation_members cm
            ON m.conversationId = cm.conversationId
            WHERE m.messageId = ? AND m.fromId = ? AND cm.user_id = m.fromId
            `, [messageId, user.id]
        )

        if (authCheck.length == 0) {
            return res.status(403).json({"message": "Message doesn't exist or you don't have permission to modify it."})
        }

        const messageData = authCheck[0];

        await connection.query(
            'DELETE FROM messages WHERE messages.messageId = ? AND messages.fromId = ?',
            [messageId, user.id]
        )

        const [conversationMembers] = await connection.query(`SELECT user_id FROM conversation_members WHERE conversation_members.conversationId = ?`, 
            [messageData.conversationId]
        )

        let [lastMessage] = await connection.query(`
            SELECT UNIX_TIMESTAMP(messages.created) AS created, messages.edited, messages.content, messages.fromId, messages.messageId, messages.conversationId, users.username
            FROM messages
            JOIN users ON users.id = messages.fromId
            WHERE messages.conversationId = ? 
            ORDER BY messages.created DESC, messages.messageId DESC LIMIT 1`
            , [messageData.conversationId])
        
        lastMessage = lastMessage.length > 0 ? lastMessage[0] : null;
        await connection.query(
            `UPDATE conversations
            SET lastMessage = ?
            WHERE conversations.conversationId = ?
            `, [lastMessage != null ? lastMessage.content : null, messageData.conversationId]
        )

        conversationMembers.forEach((member) => {
            const targetWebsocket = activeWebsockets.get(member.user_id)
            if (!targetWebsocket) return;

            targetWebsocket.send(JSON.stringify({
                type: "MESSAGE_DELETED",
                payload: {
                    messageId: messageId,
                    conversationId: messageData.conversationId,
                    newLastMessage: lastMessage
                }
            }))
        })

        return res.status(200).json({"message": "Successfuly deleted message"})
    } catch (err) {
        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

app.post("/editMessage", verifyToken, async (req, res) => {
    const user = req.user;
    const {messageId, newContent} = req.body;

    let connection;

    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [msgDetails] = await connection.query(
            `SELECT m.*, u.username
            FROM messages m
            JOIN conversation_members cm
            ON cm.conversationId = m.conversationId AND cm.user_id = m.fromId
            JOIN users u
            ON u.id = m.fromId
            WHERE m.fromId = ? AND m.messageId = ?
            LIMIT 1
            `, [user.id, messageId]
        )

        if (msgDetails.length == 0) {
            await connection.rollback();
            return res.status(403).json({"message": "Message doesn't exist or you are not authorized to edit this"})
        }

        await connection.query(
            `UPDATE messages SET content = ?, edited = TRUE WHERE messageId = ?`, [newContent, messageId]
        )

        const [conversationMembers] = await connection.query(
            `SELECT user_id FROM conversation_members WHERE conversationId = ?`, [msgDetails[0].conversationId]
        )

        let [newLastMessage] = await connection.query(
            `SELECT UNIX_TIMESTAMP(messages.created) AS created, messages.edited, messages.content, messages.fromId, messages.messageId, messages.conversationId, users.username
            FROM messages
            JOIN users ON users.id = messages.fromId
            WHERE messages.conversationId = ? 
            ORDER BY messages.created DESC, messages.messageId DESC LIMIT 1`,
            [msgDetails[0].conversationId]
        )

        newLastMessage = newLastMessage.length > 0 ? newLastMessage[0] : null;
        if (newLastMessage != null) {
            await connection.query(
                `UPDATE conversations
                SET lastMessage = ?
                WHERE conversations.conversationId = ?
                `, [newLastMessage.content, msgDetails[0].conversationId]
            )
        }

        await connection.commit();
        
        let newPayload = msgDetails[0];
        newPayload.content = newContent
        newPayload.created = Math.floor(newPayload.created.getTime() / 1000)
        newPayload.edited = 1

        conversationMembers.forEach((member) => {
            const targetWebsocket = activeWebsockets.get(member.user_id)
            if (!targetWebsocket) return

            targetWebsocket.send(JSON.stringify({
                type: "MESSAGE_EDITED",
                payload: {
                    newMessage: newPayload,
                    lastMessage: newLastMessage
                }
            }))
        })

        return res.status(201).json({"message": "Message successfuly edited"});
    } catch (err) {
        if (connection) await connection.rollback();

        console.error(err);
        return res.status(500).json({"message": "Internal Server Error"});
    } finally {
        if (connection) connection.release();
    }
})

async function prescenceUpdate(id, data) {
    let connection;

    try {
        connection = await pool.getConnection();
        const friends = friendMap.get(id);

        friends.forEach((friendId) => {
            const targetWebsocket = activeWebsockets.get(friendId);
            if (!targetWebsocket) return;

            targetWebsocket.send(JSON.stringify({
                type: "PRESCENCE_UPDATE",
                payload: {
                    id: id,
                    online: data.online,
                    lastSeen: data.lastSeen
                }
            }))
        })
    } catch (err) {
        console.error(err);
    } finally {
        if (connection) connection.release();
    }
}

const server = http.createServer(app);
const wss = new WebSocket.Server({server, path:'/ws'});
wss.on('connection', (ws, req) => {
    const authorization = req.headers["authorization"];
    const token = authorization.substring("Bearer ".length);

    if (!authorization || !authorization.startsWith("Bearer ")) {
        ws.close(1008, "Unauthorized")
        return
    }

    try {
        jwt.verify(token, tokenSecret)
    } catch {
        ws.close(1008, "Invalid Token");
        return;
    }

    const account = jwt.decode(token);
    activeWebsockets.set(account.id, ws);
    onlineUsers.put(account.id, {
        online: true,
        lastSeen: Math.floor(Date.now() / 1000)
    })

    ws.on('message', (message) => {
        console.log(`Received: ${message}`);
    });

    ws.on('close', () => {
        console.log('Client disconnected');
        activeWebsockets.delete(account.id);
        onlineUsers.delete(account.id);
    });
});

server.on("checkContinue", (req, res) => {
    res.writeContinue();
    app(req, res);
})

server.listen(port, () => {
    console.log("Server running on port: " + port)
})