<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>GACE Dashboard</title>
<style>
  body{margin:0;font-family:system-ui;background:linear-gradient(180deg,#0b1120,#0f172a);color:#e5e7eb;padding:40px}
  .glass{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:18px;padding:20px;backdrop-filter:blur(8px)}
  h1{margin-top:0}
  table{width:100%;border-collapse:collapse;margin-top:20px;display:block;overflow-x:auto}
  th,td{padding:12px;border-bottom:1px solid rgba(255,255,255,.1);text-align:left;white-space:nowrap}
  button{padding:6px 12px;border-radius:10px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.07);color:#e5e7eb;cursor:pointer}
  button.primary{background:linear-gradient(135deg,#2563eb,#8b5cf6);border:none}
  .flex{display:flex;gap:10px;align-items:center;margin-top:10px}
</style>
</head>
<body>
  <h1>GACE DNS Dashboard</h1>
  <div class="glass">
    <div class="flex">
      <select id="type">
        <option>A</option><option>CNAME</option><option>TXT</option>
      </select>
      <input id="name" placeholder="subdomain.gace.space"/>
      <input id="content" placeholder="DNS content"/>
      <button class="primary" id="addBtn">Add Record</button>
    </div>
    <table id="dnsTable">
      <thead>
        <tr><th>Type</th><th>Name</th><th>Content</th><th>ID</th><th>Actions</th></tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>
<script>
async function loadRecords(){
  const res=await fetch('/api/records');const data=await res.json();
  const tbody=document.querySelector('#dnsTable tbody');
  tbody.innerHTML='';
  if(!data.result) return tbody.innerHTML='<tr><td colspan=5>No records found.</td></tr>';
  for(const rec of data.result){
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${rec.type}</td><td>${rec.name}</td><td>${rec.content}</td><td>${rec.id}</td>
    <td><button onclick="delRecord('${rec.id}')">🗑</button></td>`;
    tbody.appendChild(tr);
  }
}
async function delRecord(id){
  if(!confirm('Delete record?'))return;
  await fetch('/api/records/'+id,{method:'DELETE'});
  loadRecords();
}
document.getElementById('addBtn').onclick=async()=>{
  const type=document.getElementById('type').value;
  const name=document.getElementById('name').value;
  const content=document.getElementById('content').value;
  await fetch('/api/records',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,name,content})});
  loadRecords();
};
loadRecords();
</script>
</body>
</html>
