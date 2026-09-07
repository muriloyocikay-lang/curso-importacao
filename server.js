const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, "public");
const DATA = path.join(ROOT, "data.json");

let db = { codes: {}, sessions: {} };
try { if (fs.existsSync(DATA)) db = JSON.parse(fs.readFileSync(DATA, "utf8")); } catch {}

function save(){ fs.writeFileSync(DATA, JSON.stringify(db, null, 2)); }
function randomCode(){
  const a="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let s="";
  for(let i=0;i<10;i++) s+=a[crypto.randomInt(a.length)];
  return s.slice(0,5)+"-"+s.slice(5);
}
function clean(){
  const now=Date.now();
  for(const [c,x] of Object.entries(db.codes)) if(x.firstUsedAt && x.expiresAt<=now) x.status="expired";
  for(const [t,s] of Object.entries(db.sessions)) if(now-s.lastSeen>65000) delete db.sessions[t];
  save();
}
setInterval(clean,30000);

function body(req){
  return new Promise((resolve,reject)=>{
    let b=""; req.on("data",d=>b+=d);
    req.on("end",()=>{ try{resolve(b?JSON.parse(b):{})}catch{resolve({})} });
    req.on("error",reject);
  });
}
function send(res,status,data,type="application/json"){
  res.writeHead(status,{"Content-Type":type,"Cache-Control":"no-store"});
  res.end(type==="application/json"?JSON.stringify(data):data);
}
function auth(req){
  const h=req.headers.authorization||"";
  const token=h.replace(/^Bearer /,"");
  const s=db.sessions[token];
  if(!s) return null;
  const c=db.codes[s.code];
  if(!c || c.status==="revoked" || c.expiresAt<=Date.now()){
    delete db.sessions[token]; save(); return null;
  }
  s.lastSeen=Date.now(); return {token,s,c};
}
function admin(req){
  return (req.headers.authorization||"")===`Bearer ${db.adminToken}`;
}

async function api(req,res,p){
  if(req.method==="POST" && p==="/api/login"){
    const b=await body(req), code=String(b.code||"").trim().toUpperCase();
    const name=String(b.name||"").trim().slice(0,40);
    const c=db.codes[code];
    if(!name) return send(res,400,{ok:false,message:"Digite seu nome."});
    if(!c || c.status==="revoked" || (c.firstUsedAt && c.expiresAt<=Date.now()))
      return send(res,401,{ok:false,message:"Código inválido ou expirado."});
    if(!c.firstUsedAt){ c.firstUsedAt=Date.now(); c.expiresAt=c.firstUsedAt+2*86400000; c.status="active"; }
    const token=crypto.randomBytes(24).toString("hex");
    db.sessions[token]={code,name,createdAt:Date.now(),lastSeen:Date.now()};
    save(); return send(res,200,{ok:true,token,expiresAt:c.expiresAt});
  }
  if(p==="/api/me"){
    const a=auth(req); if(!a) return send(res,401,{ok:false});
    return send(res,200,{ok:true,name:a.s.name,expiresAt:a.c.expiresAt});
  }
  if(req.method==="POST" && p==="/api/heartbeat"){
    const a=auth(req); if(!a) return send(res,401,{ok:false});
    save(); return send(res,200,{ok:true});
  }
  if(req.method==="POST" && p==="/api/admin/login"){
    const b=await body(req);
    if(String(b.password||"")!==ADMIN_PASSWORD) return send(res,401,{ok:false,message:"Senha incorreta."});
    db.adminToken=crypto.randomBytes(24).toString("hex"); save();
    return send(res,200,{ok:true,token:db.adminToken});
  }
  if(!admin(req)) return send(res,401,{ok:false,message:"Não autorizado."});
  if(req.method==="POST" && p==="/api/admin/codes"){
    const code=randomCode();
    db.codes[code]={createdAt:Date.now(),firstUsedAt:null,expiresAt:null,status:"unused"};
    save(); return send(res,200,{ok:true,code});
  }
  if(p==="/api/admin/codes"){
    clean();
    return send(res,200,{codes:Object.entries(db.codes).map(([code,x])=>({code,...x}))});
  }
  if(p==="/api/admin/online"){
    clean(); const now=Date.now();
    const online=Object.values(db.sessions).filter(s=>now-s.lastSeen<65000)
      .map(s=>({code:s.code,name:s.name,connectedAt:s.createdAt,lastSeen:s.lastSeen}));
    return send(res,200,{online});
  }
  if(req.method==="POST" && p==="/api/admin/revoke"){
    const b=await body(req), code=String(b.code||"").toUpperCase();
    if(db.codes[code]) db.codes[code].status="revoked";
    for(const [t,s] of Object.entries(db.sessions)) if(s.code===code) delete db.sessions[t];
    save(); return send(res,200,{ok:true});
  }
  return send(res,404,{ok:false});
}

function staticFile(req,res,p){
  let file=path.join(PUBLIC,p==="\/"? "index.html":p.replace(/^\/+/,""));
  if(!file.startsWith(PUBLIC)) return send(res,403,"Forbidden","text/plain");
  if(!fs.existsSync(file) || fs.statSync(file).isDirectory()) file=path.join(PUBLIC,"index.html");
  const ext=path.extname(file).toLowerCase();
  const types={".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".webp":"image/webp",".png":"image/png",".jpg":"image/jpeg",".ico":"image/x-icon",".mp4":"video/mp4"};
  const type=types[ext]||"application/octet-stream";
  const stat=fs.statSync(file), size=stat.size;
  const range=req.headers.range;
  if(ext===".mp4" && range){
    const m=/bytes=(\d+)-(\d*)/.exec(range);
    if(m){
      const start=Number(m[1]), end=m[2]?Number(m[2]):Math.min(start+1024*1024*4-1,size-1);
      if(start>=size) return send(res,416,"Range Not Satisfiable","text/plain");
      res.writeHead(206,{"Content-Type":type,"Content-Range":`bytes ${start}-${end}/${size}`,"Accept-Ranges":"bytes","Content-Length":end-start+1});
      return fs.createReadStream(file,{start,end}).pipe(res);
    }
  }
  res.writeHead(200,{"Content-Type":type,"Content-Length":size,"Accept-Ranges":"bytes"});
  fs.createReadStream(file).pipe(res);
}

const server=http.createServer(async(req,res)=>{
  const p=url.parse(req.url).pathname;
  try{
    if(p.startsWith("/api/")) return await api(req,res,p);
    staticFile(req,res,p);
  }catch(e){ console.error(e); send(res,500,{ok:false,message:"Erro interno"}); }
});
server.listen(PORT,()=>console.log(`Curso de Importação rodando em http://localhost:${PORT}`));
