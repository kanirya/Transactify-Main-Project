﻿using Microsoft.AspNetCore.Identity;

namespace Transactify.Data
{
    public class ApplicationUser:IdentityUser
    {
        public string Name { get; set; }
    }
}
