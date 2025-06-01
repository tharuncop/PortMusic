'use client'
import api from '../../utils/api';
import React, { use, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';


function Dashboard(){
    const router = useRouter();
    const [loading, setLoading] = useState(true);
    const [user, setUser] = useState(null);

    useEffect(() => {

        const authCheck = async() => {
            try{
                const response = await api.get('/auth/check');

                if(response.data.loggedIn){
                    setUser(response.data.user);
                }
                else{
                    router.replace('/');
                }
            }catch(error){
                console.log("Authentication error: ", error);
                router.replace('/');
            }finally{
                setLoading(false);
            }
        }
        
        authCheck();

    }, [router]);

    const handleLogout = () => {
        api.get('/auth/logout').then(()=>{
            router.push('/');
        });
    };

    if(loading){
        return <p>Loading...</p>
    }

    return(
        <>
        <h1>Welcome, {user || 'User'}</h1>
        <p>This is your dashboard page</p>
        <button onClick={handleLogout}>Logout</button>
        </>
    );

}

export default Dashboard;