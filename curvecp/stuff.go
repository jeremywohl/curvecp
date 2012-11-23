func processThings(in <-chan stuff) { 

     var tick <-chan time.Time 
     var tickinit := time.After(syncupTime) 

     for { 
         select { 

         // Always a valid case -- process any incoming values. 
         case thing <- in: 
              store(thing) 

         // Initially nil while waititing for the init signal, then 
         // always not nil 
         case <-tick: 
              doPeriodicStuff() 

         // initially not nil, but nils itself out after receives the 
         // initialization signal 
         case <-tickinit: 
              // Configure the repeat timer 
              tick = time.Tick(duration) 
              // Disable this case. 
              tickinit = nil 
         } 

     } 
}
