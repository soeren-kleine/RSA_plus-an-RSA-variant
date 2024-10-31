


\\ 1. Auxiliary functions: 

sqrt_threemodfour(y,p) = {return(Mod(y, p)^((p+1)/4))} 
sqrt_fivemodeight(y,p) = {local(ret); ret = Mod(y,p)^((p+3)/8); if(Mod(y,p)^((p-1)/4) !=Mod(1,p), ret*= Mod(2,p)^((p-1)/4)); ret} 



---------------------------------------------------------------------------------------------------------

\\ 2. Key generation: 

generate_rsa(bits) = {local(b,e,temp,p,q,d);
b = 2^bits;
e = 65537; 
temp = 1; 
while(((temp % 8 ==1)|| (temp-1 % e == 0)), temp = randomprime([b, b*2])); 
p = temp; 

b *= 4; 
temp = 1; 
while(((temp % 8 ==1)||(temp-1 % e == 0)), temp = randomprime([b, b*2])); 
q = temp; 
d = lift(Mod(e,(p-1)*(q-1))^(-1)); 

[e, d, p, q]
} 



--------------------------------------------------------------------------------------------------------- 

\\ 3. Encryption and decryption: 

rsap_encrypt(m,n,bits)={
local(expo, x,y,c); 
baseprime = randomprime([2^150, 2^190]);

expo = random([truncate((bits+1)*log(2)/log(baseprime)), truncate(log(2)*3/2*bits/log(baseprime))]);
x = baseprime^expo;
c= Mod(m,n)^x; 
y=Mod(x,n)^2; 
[c,y]
}


rsap_decrypt(p,q,c,y)={
local(d,n,t1,t2,x1,x2,m11, m12, m21, m22, m1, m2, phin);
n = p*q;
phin = (p-1)*(q-1);

if(Mod(p,4)==Mod(3,4), t1 = sqrt_threemodfour(y,p), t1 = sqrt_fivemodeight(y,p)); 
 
if(Mod(q,4)==Mod(3,4), t2 = sqrt_threemodfour(y,q), t2 = sqrt_fivemodeight(y,q));  

x1 = lift(chinese(t1,t2));
x2 = lift(chinese(t1,-t2));

if(!(gcd(x1, phin) == 1), x1 = n-x1,);
if(gcd(x1,phin)==1, x1 = lift(Mod(x1, phin)^-1); m11 = Mod(c,p)^(x1%(p-1)); m12 = Mod(c,q)^(x1%(q-1)); m1 = lift(chinese(Mod(m11,p), Mod(m12,q))), m1=0);

if(!(gcd(x2, phin) == 1), x2 = n-x2,);
if(gcd(x2,phin)==1, x2 = lift(Mod(x2, phin)^-1); m21 = Mod(c,p)^(x2%(p-1)); m22 = Mod(c,q)^(x2%(q-1)); m2 = lift(chinese(Mod(m21,p), Mod(m22,q))), m2=0);

[m1, m2]
} 



rsa_encrypt(m,e,n) = {local(c); 
c = Mod(m,n)^e; 
return(c)
}


rsa_decrypt(c,d,p,q) = {local(m1,m2,m); 
m1 = Mod(c,p)^d; 
m2 = Mod(c,q)^d; 

m = lift(chinese(Mod(m1,p), Mod(m2,q))); 
m
}


rabin_encrypt(m,n)= {return(Mod(m,n)^2)} 


rabin_decrypt(c,p,q) = {local(n,t1,t2,x1,x2,x3,x4); 
n = p*q;
if(p % 4 == 3, t1 = sqrt_threemodfour(c, p), t1 = sqrt_fivemodeight(c, p)); 
if(q % 4 == 3, t2 = sqrt_threemodfour(c, q), t2 = sqrt_fivemodeight(c, q)); 
x1 = lift(chinese(Mod(t1, p), Mod(t2, q))); 
x2 = lift(chinese(Mod(t1, p), Mod(q - t2, q))); 
x3 = n - x1; 
x4 = n - x2; 

[x1, x2, x3, x4]
} 


---------------------------------------------------------------------------------------------------------

\\ 4. Runtime test: 

runtime_test(bits, inst, i)= {
local(l, control, t0,t,e,d,p,q,t1,t2,t3,n,m,c,y,test);
l = List(); 
control = 0; 
t0 = 0; 
t = getabstime();
for(j = 1,inst, 
  [e, d, p, q] = generate_rsa(bits);
  listput(l, [e, d, p, q]));
t0 = (1.0*(getabstime() - t)) / inst; 
print("Key generation complete"); 

t = getabstime(); 
t1 = t2 = t3 = 0; 
for(j = 1, #l, 
   p = l[j][3]; 
   q = l[j][4]; 
   n = p*q;  
   for(s=1,i, 
      m = random(n); 
      [c, y] = rsap_encrypt(m, n, bits);
      test = rsap_decrypt(p, q, c, y); 
      if((m != test[1]) && (m != test[2]), control = -1; break))); 
t1 = 1.0*(getabstime() - t) / (inst*i); 
print("RSA+ done"); 

t = getabstime(); 
for(j= 1, #l, 
   e = l[j][1]; 
   d = l[j][2]; 
   p = l[j][3]; 
   q = l[j][4]; 
   n = p*q; 
   for(s=1,i, 
      m = random(n); 
      c = rsa_encrypt(m, e, n); 
      test = rsa_decrypt(c, d, p, q); 
      if(m != test, control = -2; break))); 
t2 = 1.0*(getabstime() - t) / (inst*i); 
print("RSA done"); 

t = getabstime(); 
for(j=1, # l, 
   p = l[j][3]; 
   q = l[j][4]; 
   n = p*q; 
   for(s=1, i, 
      m = random(n); 
      c = rabin_encrypt(m, n); 
      test = rabin_decrypt(c, p, q); 
      if((m != test[1]) && (m != test[2]) && (m != test[3]) && (m != test[4]), control = -3; break))); 
t3 = 1.0*(getabstime() - t) / (inst*i); 

[control, t0, t1, t2, t3]
} 

