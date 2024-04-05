package org.owasp.webgoat.lessons.deserialization;

import org.owasp.webgoat.lessons.deserialization.InsecureDeserializationTask;
import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectStreamClass;
import java.io.InvalidClassException;



public class SecureObjectInputStream extends ObjectInputStream {

    public SecureObjectInputStream(ByteArrayInputStream bytesin) throws IOException {
        super(bytesin);
    }


  @Override
  protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {

    List<String> approvedClasses = new ArrayList<String>();
    approvedClasses.add(InsecureDeserializationTask.class.getName());
    approvedClasses.add("java.time.Ser");

    if (!approvedClasses.contains(osc.getName())) {
        System.out.println("Attack Detected");
      throw new InvalidClassException("Unauthorized deserialization", osc.getName());
    }

    return super.resolveClass(osc);
  }
}

