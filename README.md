# my-nuceli-templates
Collection of my Nuclei Templates. 

**jwks.json**
This filter will check if `/jwks.json` or `/.well-known/jsk.json` is exposed. This is not a security threat, infact, it is best practise to expose these. The reason why I'm checking if this file is exposed is to perform an algorithm confusion attack.
