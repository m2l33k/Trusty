using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

class Program
{
    static void Main()
    {
        try
        {
            var dirPath = @"C:\Users\m2l3k\Desktop\testprotection";
            var dirInfo = new DirectoryInfo(dirPath);
            var acl = dirInfo.GetAccessControl();
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            acl.SetOwner(systemSid);
            dirInfo.SetAccessControl(acl);
            Console.WriteLine("SUCCESS_OWNERSHIP");
        }
        catch (Exception ex)
        {
            Console.WriteLine("FAIL_OWNERSHIP: " + ex.Message);
        }
    }
}
