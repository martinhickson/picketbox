/*
* JBoss, Home of Professional Open Source
* Copyright 2005, JBoss Inc., and individual contributors as indicated
* by the @authors tag. See the copyright.txt in the distribution for a
* full listing of individual contributors.
*
* This is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 2.1 of
* the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this software; if not, write to the Free
* Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
* 02110-1301 USA, or see the FSF site: http://www.fsf.org.
*/
package org.jboss.test;

import java.security.Principal;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.cxf.common.security.SimplePrincipal;

/**
 * Tests of org.apache.cxf.common.security.SimplePrincipal.equals.
 * Equality requires another SimplePrincipal with the same name.
 *
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 68749 $
 */
public class SimplePrincipalEqualsTestCase extends TestCase
{

   private static SimplePrincipal simplePrincipal = new SimplePrincipal("test");

   private static CustomPrincipal customPrincipal = new CustomPrincipal("test");

   public SimplePrincipalEqualsTestCase(String name)
   {
      super(name);
   }

   public void testSameName() throws Exception
   {
      assertTrue("Principals should be equal", simplePrincipal.equals(new SimplePrincipal("test")));
   }

   public void testDifferentPrincipalType() throws Exception
   {
      assertFalse("Principals should not be equal", simplePrincipal.equals(customPrincipal));
   }

   public static void main(java.lang.String[] args)
   {
      System.setErr(System.out);
      TestSuite suite = new TestSuite(SimplePrincipalEqualsTestCase.class);
      junit.textui.TestRunner.run(suite);
   }

   private static class CustomPrincipal implements Principal
   {

      private String name;

      public CustomPrincipal(String name)
      {
         this.name = name;
      }

      public String getName()
      {
         return name;
      }

      public boolean equals(Object obj)
      {
         if (!(obj instanceof CustomPrincipal))
            return false;
         CustomPrincipal another = (CustomPrincipal) obj;
         return (name == null ? another.getName() == null : name.equals(another.getName()));
      }
   }
}
