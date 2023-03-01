import { Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

import { Feature } from '../entities/feature.entity';
import { CreateFeatureDto, UpdateFeatureDto } from '../dtos/features.dtos';

@Injectable()
export class FeaturesService {
  constructor(
    @InjectModel(Feature.name) private FeatureModel: Model<Feature>,
  ) {}

  findAll() {
    return this.FeatureModel.find().exec();
  }

  findOne(id: string) {
    return this.FeatureModel.findById(id);
  }

  create(data: CreateFeatureDto) {
    const newFeature = new this.FeatureModel(data);
    return newFeature.save();
  }

  // update(id: number, changes: UpdateBrandDto) {
  //   const brand = this.findOne(id);
  //   const index = this.brands.findIndex((item) => item.id === id);
  //   this.brands[index] = {
  //     ...brand,
  //     ...changes,
  //   };
  //   return this.brands[index];
  // }

  // remove(id: number) {
  //   const index = this.brands.findIndex((item) => item.id === id);
  //   if (index === -1) {
  //     throw new NotFoundException(`Brand #${id} not found`);
  //   }
  //   this.brands.splice(index, 1);
  //   return true;
  // }
}
