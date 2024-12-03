import CredentialsProvider from "next-auth/providers/credentials"
import db from "@repo/db/client"
import bcrypt from "bcrypt"
import { number } from "zod"

export const authOptions ={
    providers:[
        CredentialsProvider({
            name:'Credentials',
            credentials:{
                phone:{label:"Phone number",type:"text",placeholder:"12132311141"},
                password:{label:"Password",type:"password"}
            },
            async authorize(credentials:any){
                const hashedPassword = await bcrypt.hash(credentials.password,10)
                const existingUser = await db.user.findFirst({
                    where:{
                        number: credentials.phone
                    }
                });
                if(existingUser){
                    const passwordValidation=await bcrypt.compare(credentials.password,existingUser.password);
                    if(passwordValidation){
                        return{
                            id: existingUser.id.toString(),
                            name:existingUser.name,
                            //shady business
                            email:existingUser.number
                        }
                    }
                    return null;
                }
                try {

                    const user =await db.user.create({
                        data:{
                            number:credentials.phone,
                            password:hashedPassword
                        }
                    });
                    return {
                        id:user.id.toString(),
                        name:user.name,
                        //shady business
                        email:user.number
                    }
                }
                catch(e){
                    console.log(e)
                }
                return null
            }
        })
    ],
    secret:process.env.JWT_SECRET||"secret",
    callbacks:{
        async session({token,session}:any){
            session.user.id=token.sub
            return session
        }
    }
}