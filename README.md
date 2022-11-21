# my-nuceli-templates
Collection of my Nuclei Templates. 

**jwks.json**</br>
This filter will check if `/jwks.json` or `/.well-known/jsk.json` is exposed. This is not a security threat if only public keys are exposed, but sometimes developers may exposed private keys in this file as well. Even if no secret key components are exposed, the knowledge of public keys may be useful for other attacks, such as algorithm and key confusion for example. 
