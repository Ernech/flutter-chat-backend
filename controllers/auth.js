const {request, response} = require('express');
const bcrypt = require('bcryptjs');
const Usuario = require('../models/usuario');
const { generarJWT } = require('../helpers/jwt');




const crearUsuario = async(req=request,res=response)=>{

    const {email,password} = req.body;

    try {

        const existeEmial = await Usuario.findOne({email});

        if(existeEmial){
            return res.status(400).json({
                of:false,
                msg:'El correo ya está registrado'
            });
        }

        const usuario = new Usuario(req.body);

        //Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password,salt);

        await usuario.save();
        //Generar JWT
        const token = await generarJWT(usuario.id);
        
        res.json({ok:true,usuario,token});

    } catch (error) {
        console.log(error);
        res.status(500).json('Hable con el administrador de la Base de datos');
    }



}

const login = async (req=request,res=response)=>{

    const {email,password}= req.body;
    try {

        const usuarioDB = await Usuario.findOne({email});
        if(!usuarioDB){
            return res.status(404).json({ok:false,msg:'Email no encontrado'});
        }

        const validPassword = bcrypt.compareSync(password,usuarioDB.password);
        if(!validPassword){
            return res.status(404).json({ok:false,msg:'Contraseña inválida'});
        }
        const token = await generarJWT(usuarioDB.id);
        return res.status(200).json({ok:true,usuario:usuarioDB,token});
    } catch (error) {
        console.log(error);
        res.status(500).json('Hable con el administrador de la Base de datos');
    }
}

const renewToken = async(req=request,res=response)=>{

    const {uid} = req;
    const token = await generarJWT(uid);
    const usuario = await Usuario.findById(uid);

    res.json({ok:true,usuario,token});
}

module.exports= {crearUsuario,login,renewToken}