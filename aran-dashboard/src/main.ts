import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { register } from 'swiper/element/bundle';

import { AppModule } from './app/app.module';

register();

platformBrowserDynamic().bootstrapModule(AppModule)
  .catch(err => console.log(err));
