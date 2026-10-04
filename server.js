// Eyeconic OTP server. Env: JWT_SECRET (32+ chars, zaroori), SMS_PROVIDER (fast2sms | msg91 | console),
// FAST2SMS_KEY / MSG91_KEY + MSG91_TEMPLATE, ADMIN_PHONES (comma separated), ALLOWED_ORIGIN (sirf agar app alag domain par ho)
const express=require("express"),crypto=require("crypto"),jwt=require("jsonwebtoken"),rl=require("express-rate-limit"),path=require("path");
const {JWT_SECRET,SMS_PROVIDER,ADMIN_PHONES="",ALLOWED_ORIGIN}=process.env;
if(!JWT_SECRET||JWT_SECRET.length<32){console.error("JWT_SECRET (32+ chars) set karo");process.exit(1)}
const app=express();app.set("trust proxy",1);app.use(express.json({limit:"10kb"}));
if(ALLOWED_ORIGIN)app.use((q,s,n)=>{s.set({"Access-Control-Allow-Origin":ALLOWED_ORIGIN,"Access-Control-Allow-Headers":"content-type,authorization","Access-Control-Allow-Methods":"GET,POST,OPTIONS"});q.method==="OPTIONS"?s.sendStatus(204):n()});
const lim=rl({windowMs:60e3,max:20,standardHeaders:true,legacyHeaders:false,handler:(q,s)=>s.status(429).json({ok:false,err:"limit"})});
const PH=/^[6-9]\d{9}$/,otps=new Map(),admins=ADMIN_PHONES.split(",").map(x=>x.trim()).filter(Boolean);
const hm=(p,o)=>crypto.createHmac("sha256",JWT_SECRET).update(p+":"+o).digest();
setInterval(()=>{const n=Date.now();for(const[k,r]of otps)if(n-(r.exp||0)>36e5&&(r.sends||[]).every(t=>n-t>36e5))otps.delete(k)},6e5).unref();

async function sendSms(phone,otp){
 if(SMS_PROVIDER==="console"){console.log("[DEV ONLY] OTP for",phone,otp);return true}
 if(SMS_PROVIDER==="msg91"){
  const u="https://control.msg91.com/api/v5/otp?template_id="+process.env.MSG91_TEMPLATE+"&mobile=91"+phone+"&authkey="+process.env.MSG91_KEY+"&otp="+otp;
  const r=await fetch(u,{method:"POST",headers:{"content-type":"application/json"},body:"{}"}),j=await r.json().catch(()=>({}));const ok=r.ok&&j.type==="success";if(!ok)console.error("msg91 refused:",r.status,JSON.stringify(j));return ok}
 if(!process.env.FAST2SMS_KEY){console.error("FAST2SMS_KEY set nahi hai (Environment mein add karo)");return false}
 const r=await fetch("https://www.fast2sms.com/dev/bulkV2",{method:"POST",headers:{authorization:process.env.FAST2SMS_KEY,"content-type":"application/json"},body:JSON.stringify({route:"otp",variables_values:otp,numbers:phone})});
 const j=await r.json().catch(()=>({}));if(j.return!==true)console.error("fast2sms refused:",r.status,JSON.stringify(j));return j.return===true}

app.post("/send-otp",lim,async(q,s)=>{
 const p=String((q.body||{}).phone||"");if(!PH.test(p))return s.json({ok:false,err:"phone"});
 const now=Date.now(),r=otps.get(p)||{sends:[]};
 if(r.next>now)return s.json({ok:false,err:"wait",wait:Math.ceil((r.next-now)/1e3)});
 r.sends=r.sends.filter(t=>now-t<36e5);if(r.sends.length>=5)return s.json({ok:false,err:"limit"});
 const o=String(crypto.randomInt(1e5,1e6));let ok=false;
 try{ok=await sendSms(p,o)}catch(e){console.error("sms error:",e.message)}
 if(!ok)return s.json({ok:false,err:"sms"});
 r.sends.push(now);Object.assign(r,{h:hm(p,o),exp:now+3e5,tries:0,next:now+3e4});otps.set(p,r);s.json({ok:true})});

app.post("/verify-otp",lim,(q,s)=>{
 const p=String((q.body||{}).phone||""),o=String((q.body||{}).otp||"");
 if(!PH.test(p))return s.json({ok:false,err:"phone"});
 const r=otps.get(p);if(!r||!r.h||Date.now()>r.exp)return s.json({ok:false,err:"expired"});
 if(r.tries>=3)return s.json({ok:false,err:"locked"});
 if(!/^\d{6}$/.test(o)||!crypto.timingSafeEqual(hm(p,o),r.h)){r.tries++;return s.json({ok:false,err:r.tries>=3?"locked":"bad",left:3-r.tries})}
 r.h=null;s.json({ok:true,token:jwt.sign({p},JWT_SECRET,{expiresIn:"30d"}),admin:admins.includes(p)})});

const auth=(q,s,n)=>{try{q.user=jwt.verify((q.headers.authorization||"").slice(7),JWT_SECRET,{algorithms:["HS256"]});n()}catch(e){s.status(401).json({ok:false,err:"auth"})}};
app.get("/me",auth,(q,s)=>s.json({ok:true,phone:q.user.p,admin:admins.includes(q.user.p)}));
app.get("/",(q,s)=>s.sendFile(path.join(__dirname,"index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Eyeconic server up"));
