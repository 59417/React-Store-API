const path = require('path');  // 引入 path
const fs = require('fs');  // 引入文件系統 fs
const jsonServer = require('json-server');  // 引入 json-server
const jwt = require('jsonwebtoken');  // 引入 node-jsonwebtoken
const server = jsonServer.create();  // create() 創建 server
// const router = jsonServer.router('db.json');  // 生成 db.json 的路由 ('/products', '/carts')
const router = jsonServer.router(path.join(__dirname, 'db.json'));  // 透過 path.join() 使用絕對路徑
const middlewares = jsonServer.defaults();

server.use(jsonServer.bodyParser);  // 使用 jsonServer 自有的解析器 bodyParser
server.use(middlewares);


// 自定義測試的接口
// server.get('/auth/login', (req, res) => {
//     console.log(req, 'Test Success!');
//     return res.status(200).json('Test Success!');
// });


// 定義獲取 user.db 文件內容
const getUsersDb = () => {
    return JSON.parse(  // JSON.parse() 轉換 .json 文件
        fs.readFileSync(path.join(__dirname, 'users.json'), 'UTF-8')
    );
};  


// 定義帳密是否授權
const isAuthenticated = ({email, password}) => {
    return (
        getUsersDb().users.findIndex(
            user => user.email === email && user.password === password
        ) !== -1  // True: 回傳符合的數組, False: 回傳 -1
    );
};


// 定義email是否註冊過
const isEmailRegistered = (email) => {
    return (
        getUsersDb().users.findIndex(
            user => user.email === email
        ) !== -1  // True: 回傳符合的數組, False: 回傳 -1
    );
};


// 定義 token 生成函式
const SECRETKEY = '389this123is8973secret029key231';
const expiresIn = '1h';  // ex. 60 (== "60s"), "2 days", "10h", "7d" , "120" (== "120ms")
const creatToken = (payload) => {
    return jwt.sign(payload, SECRETKEY, { expiresIn });
};


// 透過 post 將帳密傳給 server
server.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (isAuthenticated({ email, password })) {
        const user = getUsersDb().users.find(
            u => u.email === email && u.password === password
        );  // 獲取對應的 user 數據
        const { nickname, type } = user;  // 解構該 user 的暱稱與類別
        const jwtToken = creatToken({ nickname, type, email });  // nickname,type,emai 將返回給客戶端
        return res.status(200).json(jwtToken);
    } else {
        const status = 401;
        const message = 'Incorrect email or password';
        return res.status(status).json({ status, message });
    };
});


/* ********************* 處理新用戶註冊邏輯 *********************** */  
// 向自定義接口發送新增(post)請求
server.post('/auth/register', (req, res) => {
    // I. 拿到用戶填寫的註冊訊息
    const { nickname, email, password, type } = req.body;

    // II. 判斷 email, password 是否已存在 users.json
    if (isEmailRegistered({ email })) {
        const status = 401;
        const message = 'Email already exists';
        return res.status(status).json({ status, message });
    };
    
    // III. 新用戶將訊息寫入 user.json
    fs.readFile(path.join(__dirname, 'users.json'), (err, _data) => {
        // 1. 讀取 _data 若發生錯誤則下方指令不會執行
        if (err) {
            const status = 401;
            const message = err;
            return res.status(status).json({ status, message });
        };

        // 2. 讀取 _data 成功 > JSON.parse 解析成 data
        const data = JSON.parse(_data.toString());

        // 3. 拿到最新一筆用戶的 id (最後一筆)
        const last_item_id = data.users[data.users.length - 1].id;

        // 4. 發送新用戶資訊到 server 更新 data
        data.users.push({
            id: last_item_id + 1, 
            nickname,
            email,
            password,
            type
        });

        // 5. data 寫入 user.json
        fs.writeFile(
            path.join(__dirname, 'users.json'),
            JSON.stringify(data),
            (err, result) => {
                if (err) {
                    const status = 401;
                    const message = err;
                    res.status(status).json({ status, message });
                    return;  // 有 err 則直接跳出
                }; 
            }
        );
        // 6. 生成 JWT-token > 返回 token
        const jwtToken = creatToken({ nickname, type, email }); 
        console.log('creat token');
        return res.status(200).json(jwtToken);
    });
});
/* ************************************************************* */


// 定義驗證 token
const verifyToken = (token) => {
    return jwt.verify(token, SECRETKEY, (err, decode) => {
        decode !== undefined ? decode : err;  // 通過驗證回傳 decode
    });
};


/* ****************** 夾帶 JWT-token 發送請求 ******************** */  
/* 格式: Authorization: Bearer <token>
   ex. Authorization: Bearer vftyuihgyu.ugvhbjnfghj.iuytghjiugbj */

// 其他匹配寫法:
// server.use(/^(?!\/auth).*$/, (req, res, next) => {})
// server.use(['/carts'], (req, res, next) => {})
server.use('/carts', (req, res, next) => {
    if (
        req.headers.authorization.split(' ')[1] === 'null' ||  // token是否為空 ('null'字串)
        req.headers.authorization.split(' ')[0] !== 'Bearer'  // 判斷token是否 'Bearer ' 開頭
    ) {
        const status = 401;
        const message = 'Error in authorization format';
        res.status(status).json({ status, message });
        return;  // 有錯誤直接跳出 (下方不執行)
    };
    try {
        const verifyTokenResult = verifyToken(
            req.headers.authorization.split(' ')[1]  // 取得 token
        );
        if (verifyTokenResult instanceof Error) {  // 某物件 是否為某類別 (class) 或其子類別 (subclass) 實例 (instance)
            const status = 401;
            const message = 'Access token not provided';
            res.status(status).json({ status, message });
            return;  // 有錯誤直接跳出 (下方不執行)
        };
        next();  // 繼續執行
    } catch (error) {
        const status = 401;
        const message = 'Error token is revoked';
        res.status(status).json({ status, message });
    }
});
/* ************************************************************* */


server.use(router);
server.listen(3003, () => {  // 透過監聽端口生成服務
  console.log('JSON Server is running')
});