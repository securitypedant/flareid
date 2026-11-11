// Browser side of passkeys: turns the server's JSON options into WebAuthn calls
// and the resulting credential back into the JSON @simplewebauthn/server expects.
// Plain ES5-ish script, rendered through scriptTag() so the CSP hash covers it.

const HELPERS = `
  function b64uToBuf(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;}
  function bufToB64u(buf){var a=new Uint8Array(buf),s="";for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");}
`;

export const PASSKEY_REGISTER_SCRIPT = `(function(){
  ${HELPERS}
  var btn=document.querySelector("[data-passkey-register]"); if(!btn) return;
  var status=document.getElementById("passkey-status");
  if(!window.PublicKeyCredential){btn.disabled=true;status.textContent="This browser does not support passkeys.";return;}
  btn.addEventListener("click",function(){
    btn.disabled=true; status.textContent="Follow your browser's prompt...";
    fetch("/account/passkeys/options",{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(o){
      o.challenge=b64uToBuf(o.challenge); o.user.id=b64uToBuf(o.user.id);
      (o.excludeCredentials||[]).forEach(function(c){c.id=b64uToBuf(c.id);});
      return navigator.credentials.create({publicKey:o});
    }).then(function(cred){
      var r=cred.response;
      var body={name:(document.getElementById("passkey-name")||{}).value||"",response:{id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,
        clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},authenticatorAttachment:cred.authenticatorAttachment||undefined,
        response:{clientDataJSON:bufToB64u(r.clientDataJSON),attestationObject:bufToB64u(r.attestationObject),transports:r.getTransports?r.getTransports():[]}}};
      return fetch("/account/passkeys",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    }).then(function(r){return r.json();}).then(function(j){
      if(j.ok){location.href="/account?saved=passkey-added";} else {status.textContent=j.error||"The passkey was not added."; btn.disabled=false;}
    }).catch(function(e){status.textContent="The passkey was not added ("+(e&&e.name||"error")+")."; btn.disabled=false;});
  });
})();`;

export const PASSKEY_LOGIN_SCRIPT = `(function(){
  ${HELPERS}
  var btn=document.querySelector("[data-passkey-login]"); if(!btn) return;
  if(!window.PublicKeyCredential){btn.style.display="none";return;}
  var flow=btn.getAttribute("data-flow");
  var status=document.getElementById("passkey-login-status");
  btn.addEventListener("click",function(){
    btn.disabled=true; if(status) status.textContent="";
    fetch("/login/passkey/options?flow_id="+encodeURIComponent(flow),{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(o){
      var attempt=o.attempt; o=o.options; o.challenge=b64uToBuf(o.challenge);
      return navigator.credentials.get({publicKey:o}).then(function(cred){
        var r=cred.response;
        var resp={id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},
          response:{clientDataJSON:bufToB64u(r.clientDataJSON),authenticatorData:bufToB64u(r.authenticatorData),signature:bufToB64u(r.signature),userHandle:r.userHandle?bufToB64u(r.userHandle):undefined}};
        var f=document.createElement("form"); f.method="POST"; f.action="/login/passkey";
        [["flow_id",flow],["attempt",attempt],["response",JSON.stringify(resp)]].forEach(function(p){var i=document.createElement("input");i.type="hidden";i.name=p[0];i.value=p[1];f.appendChild(i);});
        document.body.appendChild(f); f.submit();
      });
    }).catch(function(e){btn.disabled=false; if(status) status.textContent="Passkey sign-in was cancelled or failed.";});
  });
})();`;
