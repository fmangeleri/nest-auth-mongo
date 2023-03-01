import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { ProductsController } from './controllers/products.controller';
import { BrandsController } from './controllers/brands.controller';
import { CategoriesController } from './controllers/categories.controller';
import { ProductsService } from './services/products.service';
import { BrandsService } from './services/brands.service';
import { CategoriesService } from './services/categories.service';
import { Product, ProductSchema } from './entities/product.entity';
import { Brand, BrandSchema } from './entities/brand.entity';
import { Feature, FeatureSchema } from './entities/feature.entity';
import { FeaturesController } from './controllers/features.controller';
import { FeaturesService } from './services/features.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: Product.name,
        schema: ProductSchema,
      },
      {
        name: Brand.name,
        schema: BrandSchema,
      },
      {
        name: Feature.name,
        schema: FeatureSchema,
      },
    ]),
  ],
  controllers: [
    ProductsController,
    CategoriesController,
    BrandsController,
    FeaturesController,
  ],
  providers: [
    ProductsService,
    BrandsService,
    CategoriesService,
    FeaturesService,
  ],
  exports: [ProductsService],
})
export class ProductsModule {}
