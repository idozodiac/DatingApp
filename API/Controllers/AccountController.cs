using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Storage;
using API.Data;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using API.Interfaces;
using API.Services;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {

       
        
        private readonly ITokenService _tokenService;
        
        private readonly DataContext _context;
        public AccountController(DataContext context, ITokenService tokenService){
            _tokenService = tokenService;
          
            
            _context = context;
        }

        [HttpPost("register")]

        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto){ // registration
            if(await UserExists (registerDto.Username)) return BadRequest("Username is taken");

            using var hmac = new HMACSHA512(); // using makes sure that its disposed correctly

            var user = new AppUser{
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            
            _context.Users.Add(user);
            await _context.SaveChangesAsync(); // save user in database

            return new UserDto{
                Username = user.UserName,  
                Token = _tokenService.CreateToken(user)
            };

        }

        [HttpPost("login")]

        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){
            var user = await _context.Users
            .SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

            if(user == null) return Unauthorized("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i = 0; i < computeHash.Length; i++){
                if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid passward");
            }
             return new UserDto{
                Username = user.UserName,  
                Token = _tokenService.CreateToken(user)
            };

        }


        private async Task<bool> UserExists(string username){

            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());

        }
    }
}

